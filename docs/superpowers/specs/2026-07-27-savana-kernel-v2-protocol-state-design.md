# Savana Kernel V2 Protocol and State Design

> Date: 2026-07-27
>
> Status: normative companion; written-spec review pending
>
> Parent: [Savana Secure Kernel V2](./2026-07-27-savana-secure-kernel-v2-design.md)

## 1. Scope and invariants

This specification freezes:

- V1/V2 separation;
- every V2 local endpoint and operation class;
- common wire, error, replay, limit, and sensitive-record rules;
- the G3 label/provenance algebra;
- ontology, projection, descriptor, planner, and validator languages;
- ingress, action, approval, quota, execution, result, vault, and recovery
  state machines;
- the kerneld and execd durable journal protocol;
- the runtime security-state identity;
- the initial V2 cryptographic suite.

No V2 mutation operation may be opened in a dispatcher until its complete
schema, transition, replay behavior, resource accounting, audit behavior,
restart behavior, vectors, and negative endpoint tests pass.

Normative words `MUST`, `MUST NOT`, `SHALL`, and `SHALL NOT` are requirements.

## 2. Version and decoder isolation

V1 and V2 use different Rust types:

```rust
ClientMessageV1
ServerMessageV1
OperationV1

ClientMessageV2
ServerMessageV2
AgentControlOperationV2
KernelAgentOperationV2
KernelIngressOperationV2
ExecutorOperationV2
ApprovalAgentOperationV2
ApprovalIngressOperationV2
ApprovalAdminOperationV2
```

V1 enums are not extended, renamed, or reinterpreted. A V1 decode failure is
never retried with a V2 decoder, and a V2 failure is never retried with V1.

Every handshake message starts with this exact 16-byte prefix:

```text
offset  size  value
0       8     ASCII "SAVANA2\0"
8       2     protocol_major, unsigned big-endian; exactly 2
10      2     protocol_minor, unsigned big-endian; exactly 0
12      2     suite_id, unsigned big-endian; exactly 1
14      1     EndpointRoleV2
15      1     HandshakeMessageKindV2
```

The closed role and handshake-kind values are:

```text
EndpointRoleV2
1  JarvisAgentControl
2  AgentKernel
3  IngressKernel
4  KernelExecutor
5  AgentApproval
6  IngressApproval
7  ApprovalAdmin

HandshakeMessageKindV2
1  ClientHello
2  ServerHello
3  ClientFinish
```

Any other magic, length, version, suite, role, or kind closes silently before a
CBOR decoder is selected. The prefix selects the protocol major and exact
endpoint decoder before any variable-length data is decoded. Once major 2 and
one endpoint role are authenticated, that connection uses exactly one
role-specific V2 decoder. Reusing a numeric tag from V1 or another V2 endpoint
does not create compatibility. A V2 prefix is never passed to any V1 parser,
even after a later handshake or application error.

Final required-mode endpoints advertise only protocol `2.0`. Migration builds
that temporarily carry V1 and V2 use separate listener descriptors and
separate service identities.

## 3. Common wire ABI

### 3.1 Canonical form

Every metadata structure is a definite-length canonical CBOR array in the
field order shown in this document. These rules are part of the ABI:

- a struct is an array of exactly its declared field count;
- a unit struct and an empty operation body are the zero-element array `[]`;
- an enum is `[tag_u16, field_0, ...]`; a unit variant is `[tag_u16]`;
- enum tags are the explicit values in this document and never Rust source
  ordinals;
- `Option<T>` is CBOR `null` for `None` and the exact encoding of `T` for
  `Some`; `null` is legal nowhere else;
- `bool` uses only the CBOR `false` and `true` simple values;
- `u8`, `u16`, `u32`, `u64`, and `i64` describe accepted mathematical ranges,
  not fixed-width CBOR integers; the shortest CBOR integer form is mandatory;
- a fixed byte type is one definite-length byte string of exactly its declared
  length;
- a vector is one definite-length array and is rejected before allocation when
  its element count exceeds its declared bound;
- a `BoundedSortedVec` is strictly increasing by the canonical encoded bytes
  of its key element; identifiers therefore sort by their NFC UTF-8 bytes;
- duplicate sorted keys and duplicate set members are rejected;
- a signed object is `[payload_bstr, signer_key_id, signature_bstr64]`, where
  `payload_bstr` contains the exact canonical bytes of its declared unsigned
  payload. Verification uses that byte string directly and never a re-encoded
  object.

V2 forbids:

- maps;
- floats;
- CBOR semantic tags;
- indefinite arrays, strings, or byte strings;
- non-shortest integer or length forms;
- unknown enum tags;
- omitted or trailing fields;
- invalid UTF-8;
- CBOR `undefined`, unassigned simple values, and non-boolean simple values;
- unconsumed trailing bytes.

Text fields that represent identifiers require NFC. Original input chunks are
opaque bytes until the input-runtime normalization transition.

Primitive widths:

```text
RequestIdV2             16 bytes
Digest32                32 bytes
Nonce32                 32 bytes
CapabilityTokenV2       32 bytes
BootIdV2                32 bytes
Ed25519KeyIdV2          32 bytes
HpkeX25519KeyIdV2       32 bytes
ReplayAeadKeyIdV2       32 bytes
Ed25519SignatureV2      64 bytes
UnixMillis              unsigned u64
MonotonicNanos          unsigned u64
operation tag           unsigned u16
enum tag                unsigned u16
```

Key identifiers are full digests and family-separated:

```text
Ed25519KeyIdV2 =
  SHA-256("savana.ed25519-key-id.v2\0" || ed25519_public_key_bstr32)

HpkeX25519KeyIdV2 =
  SHA-256("savana.hpke-x25519-key-id.v2\0" ||
          hpke_x25519_public_key_bstr32)
```

The signed-object `signer_key_id` is always `Ed25519KeyIdV2`. Handshake
signing IDs use the same type. HPKE fields use only `HpkeX25519KeyIdV2`.
Cross-family decoding, truncation, alternate domains, and 16-byte key IDs are
rejected before lookup.

`ReplayAeadKeyIdV2` is a distinct CSPRNG-generated, keystore-owned 32-byte
identifier for a non-exportable XChaCha20-Poly1305 key. It is not a digest of
key bytes and has no decoder as `Digest32`, `Ed25519KeyIdV2`, or
`HpkeX25519KeyIdV2`.

All capability constructors and byte accessors are crate-private. `Debug`
prints only the type name and `<opaque>`.

`EmptyV2` is the exact CBOR byte string `0x80`, the zero-element array. No
operation may substitute `null`, an omitted body, or an empty byte string.

### 3.2 Request and response

After the encrypted handshake, a request begins with:

```rust
struct RequestHeaderV2 {
    protocol_major: u16,       // exactly 2
    protocol_minor: u16,       // exactly 0
    endpoint_role: EndpointRoleV2,
    request_id: RequestIdV2,
    deadline_unix_ms: UnixMillis,
}
```

The canonical request is:

```text
[RequestHeaderV2, operation_tag_u16, operation_body]
```

The canonical response is:

```text
[request_id_bstr16, status_u8, payload]

status 0: success payload for the exact operation
status 1: [PublicStableCodeV2_u16]
```

An authenticated request receives at most one response. Pre-authentication,
handshake, role, sequence, AEAD, canonical, and pre-request framing failures
close silently.

The clear record header and decrypted request duplicate protocol, role,
request ID, and operation tag deliberately. Before operation-body decoding,
the receiver MUST compare every duplicate for exact equality. A mismatch
closes silently and does not create a replay record or audit object.

### 3.3 Operation classes

```rust
enum OperationClassV2 {
    Query = 1,
    SensitiveQuery = 2,
    IdempotentMutation = 3,
    OneWayMutation = 4,
    SensitiveIdempotentMutation = 5,
    SensitiveOneWayMutation = 6,
}
```

`Sensitive` means that every content-bearing request and response field uses
the zeroizing decoder and storage types. All transport plaintext, sensitive or
not, has the same 8 MiB record ceiling. Every mutation has a replay record
committed atomically with its state change. A one-way mutation additionally
consumes or permanently reserves an authorization object and may not return to
an earlier state.

### 3.4 Public stable codes and oracle rule

Only this closed `u16` table may appear in a status-1 response:

| Value | Code |
|---:|---|
| 20 | `InvalidReference` |
| 23 | `StateConflict` |
| 24 | `IdempotencyConflict` |
| 25 | `CancellationTooLate` |
| 30 | `LimitExceeded` |
| 31 | `Overloaded` |
| 32 | `DeadlineExceeded` |
| 33 | `Cancelled` |
| 40 | `PolicyDenied` |
| 41 | `PolicyExpired` |
| 42 | `ArtifactRollback` |
| 43 | `RegistryMismatch` |
| 44 | `OntologyMismatch` |
| 45 | `ProjectionMismatch` |
| 50 | `ModelUnavailable` |
| 51 | `ModelContract` |
| 52 | `InputDenied` |
| 53 | `InputMalformed` |
| 60 | `ApprovalDenied` |
| 61 | `ApprovalExpired` |
| 62 | `ApprovalReplay` |
| 63 | `ApprovalBindingMismatch` |
| 70 | `ValidatorMissing` |
| 71 | `ValidatorRejected` |
| 72 | `ValidatorBindingMismatch` |
| 80 | `ExecutionFailedNoEffect` |
| 81 | `ExecutionIndeterminate` |
| 82 | `ResultUnavailable` |
| 90 | `StorageUnavailable` |
| 91 | `AuditUnavailable` |
| 92 | `EntropyUnavailable` |
| 93 | `ServiceUnavailable` |
| 255 | `InternalFatal` |

Producer strings and provider errors never become public codes.

Protocol malformed/non-canonical/limit/version, peer, transcript, role,
unknown-handle, stale-handle, and binding-mismatch reasons are private audit
reasons and are not values of `PublicStableCodeV2`. Before a fully
authenticated canonical request exists they close silently. Afterwards all
unknown, stale, wrong-type, wrong-client, wrong-peer, wrong-boot, wrong-run,
wrong-purpose, and wrong-state capability failures exposed to a caller
collapse to `InvalidReference`, except that the exact owner of a live object
may receive `StateConflict`. Private audit may distinguish the causes.

The exact allowed public-code sets used by the operation tables are:

```text
E_HEALTH =
  { ServiceUnavailable, InternalFatal }

E_QUERY =
  { InvalidReference, DeadlineExceeded, ServiceUnavailable, InternalFatal }

E_CONTROL_MUTATION =
  { InvalidReference, StateConflict, IdempotencyConflict,
    CancellationTooLate, LimitExceeded, Overloaded, DeadlineExceeded,
    Cancelled, StorageUnavailable, AuditUnavailable, EntropyUnavailable,
    ServiceUnavailable, InternalFatal }

E_INPUT =
  E_CONTROL_MUTATION ∪
  { InputDenied, InputMalformed, ModelUnavailable, ModelContract,
    PolicyDenied, PolicyExpired }

E_POLICY =
  E_CONTROL_MUTATION ∪
  { PolicyDenied, PolicyExpired, RegistryMismatch, OntologyMismatch,
    ProjectionMismatch, ValidatorMissing, ValidatorRejected,
    ValidatorBindingMismatch }

E_APPROVAL =
  E_CONTROL_MUTATION ∪
  { ApprovalDenied, ApprovalExpired, ApprovalReplay,
    ApprovalBindingMismatch }

E_EXECUTION =
  E_POLICY ∪ E_APPROVAL ∪
  { ExecutionFailedNoEffect, ExecutionIndeterminate, ResultUnavailable }

E_ADMIN =
  { InvalidReference, StateConflict, IdempotencyConflict, LimitExceeded,
    Overloaded, DeadlineExceeded, StorageUnavailable, AuditUnavailable,
    EntropyUnavailable, ServiceUnavailable, InternalFatal }
```

An implementation may return only a member of the error-set ID assigned to the
operation below. It must not refine a public error with text, nested causes, a
provider code, or a second response.

### 3.5 Opaque types and security-critical enum registry

Every capability/handle listed below is a distinct Rust newtype encoded as one
32-byte CBOR byte string:

```text
TaskHandleV2,
NewTaskPreparationHandleV2,
AgentUiAuthenticationPreparationHandleV2,
IngressUiAuthenticationPreparationHandleV2,
KernelIngressBootstrapTransferCapabilityV2,
IngressUiAuthenticationTransferCapabilityV2,
ApprovalDisplayAuthenticationTransferCapabilityV2,
AgentUiAuthenticationTransferCapabilityV2,
IngressUiAuthenticationSettlementTransferCapabilityV2,
AgentUiAuthenticationSettlementTransferCapabilityV2,
IngressUiPreAuthenticationTabCapabilityV2,
ApprovalDisplayUiPreAuthenticationTabCapabilityV2,
AgentUiPreAuthenticationTabCapabilityV2,
IngressUiAuthenticationRecordHandleV2,
AgentUiAuthenticationRecordHandleV2,
IngressUiAuthenticationBrowserCeremonyCapabilityV2,
ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
AgentUiAuthenticationBrowserCeremonyCapabilityV2,
IngressUiAuthorizationHandleV2, AgentUiAuthorizationHandleV2,
ApprovalTabSessionCapabilityV2, ApprovalDecisionCeremonyCapabilityV2,
IngressWriteCapabilityV2,
InputSessionHandleV2, ParserExtractionHandleV2, PendingIngressHandleV2,
AgentSessionHandleV2,
AgentTabSessionCapabilityV2, IngressTabSessionCapabilityV2,
RunHandleV2, ValueHandleV2,
MaskedDocumentHandleV2, PlanStepHandleV2,
PlannerTicketHandleV2, ToolHandleV2, ActionIntentHandleV2,
PendingToolCallHandleV2, IngressKernelApprovalHandleV2,
ToolKernelApprovalHandleV2, ReleaseKernelApprovalHandleV2,
IngressApprovalRecordHandleV2, ToolApprovalRecordHandleV2,
ReleaseApprovalRecordHandleV2, ExecutionTicketHandleV2,
ExecutionHandleV2, PendingReleaseHandleV2,
ReleaseTicketHandleV2, ReleaseHandleV2, EnrollmentHandleV2,
EnrollmentCeremonyCapabilityV2,
KernelAgentViewCursorV2, AgentBrowserViewCursorCapabilityV2
```

They are generated with a CSPRNG, stored only as
`SHA-256(type_domain || token)`, compared in constant time after hashing, and
never converted between types. Except `TaskHandleV2`'s query-only rule, each
binds installation, issuing service/client identity, OS peer, service boot,
run/object/type, purpose, active manifest, creation/expiry, revocation, and
consumption.

The following registry is exhaustive. `Issuer/resolver` names the service
that both creates the token and owns its independently typed hash index; a
relay never becomes a resolver. `POST relay` means the browser may carry the
raw token only in the named fixed form body. `Once` means the first valid
transition consumes it atomically; `boot` means the issuer boot is part of
the lookup key. No implementation may share a token store, decoder, or hash
domain between rows.

| Type | Exact `type_domain` bytes | Issuer/resolver and only accepting surface | Carrier; lifetime |
|---|---|---|---|
| `TaskHandleV2` | `"SAVANA_TASK_HANDLE_V2\0"` | agentd; JARVIS 11 query and same-boot JARVIS 12 | JARVIS CBOR; query through tombstone retention |
| `NewTaskPreparationHandleV2` | `"SAVANA_NEW_TASK_PREPARATION_HANDLE_V2\0"` | kerneld; AgentKernel 39 or 42 | agentd UDS; boot, operation-state bound |
| `AgentUiAuthenticationPreparationHandleV2` | `"SAVANA_AGENT_UI_AUTH_PREPARATION_HANDLE_V2\0"` | kerneld; AgentKernel 40 | agentd UDS; once, boot |
| `IngressUiAuthenticationPreparationHandleV2` | `"SAVANA_INGRESS_UI_AUTH_PREPARATION_HANDLE_V2\0"` | kerneld; IngressKernel 47 | ingressd UDS; once, boot |
| `KernelIngressBootstrapTransferCapabilityV2` | `"SAVANA_KERNEL_INGRESS_BOOTSTRAP_TRANSFER_V2\0"` | kerneld; IngressKernel 46 after 8767 relay | POST relay then ingressd UDS; once, boot |
| `IngressUiAuthenticationTransferCapabilityV2` | `"SAVANA_INGRESS_UI_AUTH_TRANSFER_V2\0"` | approvald; 8766 UI-auth accept for `IngressInput` | POST relay; once, approvald boot |
| `ApprovalDisplayAuthenticationTransferCapabilityV2` | `"SAVANA_APPROVAL_DISPLAY_AUTH_TRANSFER_V2\0"` | approvald; 8766 UI-auth accept for `ApprovalDisplay` | POST relay; once, approvald boot |
| `AgentUiAuthenticationTransferCapabilityV2` | `"SAVANA_AGENT_UI_AUTH_TRANSFER_V2\0"` | approvald; 8766 UI-auth accept for `AgentContent` | POST relay; once, approvald boot |
| `IngressUiAuthenticationSettlementTransferCapabilityV2` | `"SAVANA_INGRESS_UI_AUTH_SETTLEMENT_TRANSFER_V2\0"` | approvald; IngressApproval 23 after 8767 relay | POST relay then ingressd UDS; once, approvald boot |
| `AgentUiAuthenticationSettlementTransferCapabilityV2` | `"SAVANA_AGENT_UI_AUTH_SETTLEMENT_TRANSFER_V2\0"` | approvald; AgentApproval 23 after 8768 relay | POST relay then agentd UDS; once, approvald boot |
| `IngressUiPreAuthenticationTabCapabilityV2` | `"SAVANA_INGRESS_UI_PREAUTH_TAB_V2\0"` | approvald; 8766 UI-auth begin ingress variant | 8766 body/JS memory; once, boot |
| `ApprovalDisplayUiPreAuthenticationTabCapabilityV2` | `"SAVANA_APPROVAL_DISPLAY_UI_PREAUTH_TAB_V2\0"` | approvald; 8766 UI-auth begin display variant | 8766 body/JS memory; once, boot |
| `AgentUiPreAuthenticationTabCapabilityV2` | `"SAVANA_AGENT_UI_PREAUTH_TAB_V2\0"` | approvald; 8766 UI-auth begin agent variant | 8766 body/JS memory; once, boot |
| `IngressUiAuthenticationRecordHandleV2` | `"SAVANA_INGRESS_UI_AUTH_RECORD_HANDLE_V2\0"` | approvald; IngressApproval 23 | ingressd UDS; boot and record expiry |
| `AgentUiAuthenticationRecordHandleV2` | `"SAVANA_AGENT_UI_AUTH_RECORD_HANDLE_V2\0"` | approvald; AgentApproval 23 | agentd UDS; boot and record expiry |
| `IngressUiAuthenticationBrowserCeremonyCapabilityV2` | `"SAVANA_INGRESS_UI_AUTH_BROWSER_CEREMONY_V2\0"` | approvald; 8766 UI-auth finish ingress variant | 8766 body/JS memory; once, boot |
| `ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2` | `"SAVANA_APPROVAL_DISPLAY_UI_AUTH_BROWSER_CEREMONY_V2\0"` | approvald; 8766 UI-auth finish display variant | 8766 body/JS memory; once, boot |
| `AgentUiAuthenticationBrowserCeremonyCapabilityV2` | `"SAVANA_AGENT_UI_AUTH_BROWSER_CEREMONY_V2\0"` | approvald; 8766 UI-auth finish agent variant | 8766 body/JS memory; once, boot |
| `IngressUiAuthorizationHandleV2` | `"SAVANA_INGRESS_UI_AUTHORIZATION_HANDLE_V2\0"` | kerneld; IngressKernel 40 | ingressd UDS; once, boot |
| `AgentUiAuthorizationHandleV2` | `"SAVANA_AGENT_UI_AUTHORIZATION_HANDLE_V2\0"` | kerneld; AgentKernel 20 | agentd UDS; once, boot |
| `ApprovalTabSessionCapabilityV2` | `"SAVANA_APPROVAL_TAB_SESSION_V2\0"` | approvald; 8766 display/decision-begin | 8766 body/JS memory; tab/boot |
| `ApprovalDecisionCeremonyCapabilityV2` | `"SAVANA_APPROVAL_DECISION_CEREMONY_V2\0"` | approvald; 8766 decision-finish | 8766 body/JS memory; once, boot |
| `IngressWriteCapabilityV2` | `"SAVANA_INGRESS_WRITE_CAPABILITY_V2\0"` | kerneld; IngressKernel 41 | ingressd UDS; session/boot |
| `InputSessionHandleV2` | `"SAVANA_INPUT_SESSION_HANDLE_V2\0"` | kerneld; IngressKernel 42, 44, 45, or 48 | ingressd UDS; boot |
| `ParserExtractionHandleV2` | `"SAVANA_PARSER_EXTRACTION_HANDLE_V2\0"` | kerneld; IngressKernel 49 or 50 | ingressd UDS; session/worker-job/boot |
| `PendingIngressHandleV2` | `"SAVANA_PENDING_INGRESS_HANDLE_V2\0"` | kerneld; IngressKernel 43 or 45 | ingressd UDS; boot |
| `AgentSessionHandleV2` | `"SAVANA_AGENT_SESSION_HANDLE_V2\0"` | kerneld; AgentKernel session operations | agentd UDS; boot |
| `AgentTabSessionCapabilityV2` | `"SAVANA_AGENT_TAB_SESSION_V2\0"` | agentd; 8768 view/action | 8768 body/JS memory; tab/agentd boot |
| `IngressTabSessionCapabilityV2` | `"SAVANA_INGRESS_TAB_SESSION_V2\0"` | ingressd; 8767 input operations | 8767 body/JS memory; tab/ingressd boot |
| `RunHandleV2` | `"SAVANA_RUN_HANDLE_V2\0"` | kerneld; AgentKernel run operations | agentd UDS; boot |
| `ValueHandleV2` | `"SAVANA_VALUE_HANDLE_V2\0"` | kerneld; AgentKernel value/planner/tool operations | agentd UDS; boot |
| `MaskedDocumentHandleV2` | `"SAVANA_MASKED_DOCUMENT_HANDLE_V2\0"` | kerneld; AgentKernel 31, 32, or 36 | agentd UDS; boot |
| `PlanStepHandleV2` | `"SAVANA_PLAN_STEP_HANDLE_V2\0"` | kerneld; AgentKernel 26 | agentd UDS; boot |
| `PlannerTicketHandleV2` | `"SAVANA_PLANNER_TICKET_HANDLE_V2\0"` | kerneld; AgentKernel 24 | agentd UDS; once, boot |
| `ToolHandleV2` | `"SAVANA_TOOL_HANDLE_V2\0"` | kerneld; AgentKernel 26 | agentd UDS; manifest/boot |
| `ActionIntentHandleV2` | `"SAVANA_ACTION_INTENT_HANDLE_V2\0"` | kerneld; AgentKernel 30 status target | agentd UDS; boot |
| `PendingToolCallHandleV2` | `"SAVANA_PENDING_TOOL_CALL_HANDLE_V2\0"` | kerneld; AgentKernel 27 or 28 | agentd UDS; boot/state |
| `IngressKernelApprovalHandleV2` | `"SAVANA_INGRESS_KERNEL_APPROVAL_HANDLE_V2\0"` | kerneld; IngressKernel 43 | ingressd UDS; once, boot |
| `ToolKernelApprovalHandleV2` | `"SAVANA_TOOL_KERNEL_APPROVAL_HANDLE_V2\0"` | kerneld; AgentKernel 28 | agentd UDS; once, boot |
| `ReleaseKernelApprovalHandleV2` | `"SAVANA_RELEASE_KERNEL_APPROVAL_HANDLE_V2\0"` | kerneld; AgentKernel 33 | agentd UDS; once, boot |
| `IngressApprovalRecordHandleV2` | `"SAVANA_INGRESS_APPROVAL_RECORD_HANDLE_V2\0"` | approvald; IngressApproval 21 | ingressd UDS; boot, durable record re-registerable |
| `ToolApprovalRecordHandleV2` | `"SAVANA_TOOL_APPROVAL_RECORD_HANDLE_V2\0"` | approvald; AgentApproval 21 tool variant | agentd UDS; boot, durable record re-registerable |
| `ReleaseApprovalRecordHandleV2` | `"SAVANA_RELEASE_APPROVAL_RECORD_HANDLE_V2\0"` | approvald; AgentApproval 21 release variant | agentd UDS; boot, durable record re-registerable |
| `ExecutionTicketHandleV2` | `"SAVANA_EXECUTION_TICKET_HANDLE_V2\0"` | kerneld; AgentKernel 29 or 30 | agentd UDS; once/status, boot |
| `ExecutionHandleV2` | `"SAVANA_EXECUTION_HANDLE_V2\0"` | kerneld; AgentKernel 30 | agentd UDS; boot |
| `PendingReleaseHandleV2` | `"SAVANA_PENDING_RELEASE_HANDLE_V2\0"` | kerneld; AgentKernel 33 or 35 | agentd UDS; boot/state |
| `ReleaseTicketHandleV2` | `"SAVANA_RELEASE_TICKET_HANDLE_V2\0"` | kerneld; AgentKernel 34 or 35 | agentd UDS; once/status, boot |
| `ReleaseHandleV2` | `"SAVANA_RELEASE_HANDLE_V2\0"` | kerneld; AgentKernel 35 | agentd UDS; boot |
| `EnrollmentHandleV2` | `"SAVANA_ENROLLMENT_HANDLE_V2\0"` | approvald; 8766 enrollment-begin | admin response then 8766 body; once, boot/expiry |
| `EnrollmentCeremonyCapabilityV2` | `"SAVANA_ENROLLMENT_CEREMONY_V2\0"` | approvald; 8766 enrollment-finish | 8766 body/JS memory; once, boot |
| `KernelAgentViewCursorV2` | `"SAVANA_KERNEL_AGENT_VIEW_CURSOR_V2\0"` | kerneld; AgentKernel 31 | agentd UDS; document/boot |
| `AgentBrowserViewCursorCapabilityV2` | `"SAVANA_AGENT_BROWSER_VIEW_CURSOR_V2\0"` | agentd; 8768 agent-view | 8768 body/JS memory; tab/document/boot |

Every row also binds the exact purpose, origin where applicable, active
manifest/generation, object state, issuer boot, expiry, and permitted peer.
Relay rows bind the initiating authenticated service, browser return origin,
and final UDS presenter as separate fields; they never overload a generic
“client identity.” The relay can carry but cannot resolve, retarget, inspect,
or consume the token.
Unknown table entries, valid tokens presented to another row, wrong carriers,
and tokens surviving a prohibited restart fail before state lookup. The
`JarvisBootstrapSelectorV2` hash domain is exactly
`"SAVANA_JARVIS_BOOTSTRAP_SELECTOR_V2\0"`; it is agentd-owned,
non-authorizing, and resolvable only by 8765 bootstrap continue.

`PlannerSlotRefV2`, `AgentMaskedDocumentRefV2`,
`AgentPlanStepRefV2`, `AgentPendingToolCallRefV2`,
`AgentExecutionTicketRefV2`, `AgentReleaseTicketRefV2`,
`AgentExecutionRefV2`, and `AgentReleaseRefV2` are distinct 16-byte
non-capabilities.
`InternalSlotDigestV2`, `ActionIntentIdV2`, and every
`*Digest` are 32-byte non-capability values.
`JarvisBootstrapSelectorV2` is a distinct unpredictable 32-byte
non-capability selector derived by the current-boot PRF below. It is stored
hashed and may select only a fixed,
contentless bootstrap preparation; possession never authorizes content,
input, approval, cancellation, or task status.

Security-critical discriminants are:

```text
FixedOriginV2
1 Jarvis8765, 2 Approval8766, 3 Ingress8767, 4 Agent8768

UiActionV2
0 None, 1 OpenIngress, 2 OpenApproval, 3 OpenAgent

JarvisBootstrapActionV2
0 None, 1 OpenIngress, 2 OpenApproval, 3 OpenAgent

BootstrapKindV2
1 Ingress, 2 Approval, 3 Agent

PublicServiceStateV2
1 Starting, 2 Ready, 3 DegradedFailClosed, 4 Fenced

PublicTaskStatusV2
1 AwaitingUiAuthentication, 2 AwaitingInput, 3 Processing,
4 AwaitingIngressApproval, 5 Ready, 6 Running, 7 Dispatching, 8 Succeeded,
9 EffectSucceededOutputQuarantined, 10 PolicyDenied, 11 FailedNoEffect,
12 Indeterminate, 13 Cancelled, 14 Expired

UiAuthenticationPurposeV2
1 IngressInput, 2 ApprovalDisplay, 3 AgentContent

JarvisOsPeerClassV2
1 LinuxJarvisService, 2 MacOsJarvisApplication

AgentSessionStatusV2
1 AwaitingAuthentication, 2 Ready, 3 Running, 4 Closed,
5 Expired, 6 RestartInvalidated, 7 Indeterminate

InputChannelV2
1 OriginalSource, 2 ExtractedPage, 3 ChatText

InputPublicStateV2
1 Granted, 2 Receiving, 3 Finalizing, 4 AwaitingApproval, 5 Committing,
6 CommittedUnclaimed, 7 AgentClaimed, 8 Denied, 9 Aborted, 10 Expired,
11 FailedClosed, 12 RestartInvalidated, 13 AgentAuthPending

AgentAuthenticationRecoveryPhaseV2
1 Prepared, 2 AuthenticatedAwaitingClaim, 3 Claimed, 4 RestartInvalidated

ExecutionStatusTargetV2
1 Intent, 2 Ticket, 3 Execution

ReleaseStatusTargetV2
1 Pending, 2 Ticket, 3 Release

PublicExecutionStatusV2
1 Prepared, 2 Dispatching, 3 ResultGatePending, 4 Succeeded,
5 EffectSucceededOutputQuarantined, 6 FailedNoEffect, 7 Indeterminate

PublicFailureClassV2
1 Policy, 2 Input, 3 Approval, 4 Connector, 5 Infrastructure,
6 ResultGate, 7 Audit, 8 ReleaseEvidence

ExecutorStatusV2
1 Unknown, 2 Prepared, 3 EffectStarted, 4 CompletionAvailable,
5 FailedNoEffect, 6 Indeterminate, 7 Acknowledged

ExecutorFailureClassV2
1 EnvelopeRejectedBeforeEffect, 2 FencedBeforeEffect,
3 ConnectorUnavailableBeforeEffect, 4 ConnectorRejectedBeforeEffect,
5 ResourceFailureBeforeEffect

ApprovalSettlementViewV2
1 Pending, 2 Denied, 3 Expired, 4 Approved

AgentApprovalRecordTargetV2
1 Tool, 2 Release

VaultPublicStateV2
1 Pending, 2 Live, 3 ReleaseAuthorized, 4 Dispatching, 5 Released,
6 Revoked, 7 Expired, 8 Indeterminate, 9 RestartInvalidated

CredentialPublicStateV2
1 Active, 2 Revoked, 3 Unknown

AgentContentStateV2
1 Ready, 2 Running, 3 AwaitingApproval, 4 Closed,
5 Failed, 6 Indeterminate

EvaluateToolCallResponseV2
1 Denied, 2 NeedsApproval, 3 Allowed

ActionIntentCurrentStateV2
1 Proposed, 2 Evaluating, 3 Denied, 4 AwaitingApproval,
5 Authorized, 6 Dispatched, 7 Terminal

InputStatusTargetV2
1 Session, 2 Pending
```

`PublicFailureClassV2::Audit` is canonical only inside
`EffectSucceededOutputQuarantined`; pairing it with `PolicyDenied` or
`FailedNoEffect` is rejected. Conversely, a known-success audit-publication
failure must use that exact class and may not be relabeled Infrastructure,
ResultGate, or Indeterminate.

The quarantine class/subject matrix is closed. A tool-execution quarantine
permits only `ResultGate` or `Audit`; a final-release quarantine permits only
`ReleaseEvidence` or `Audit`. Tool/`ReleaseEvidence`,
release/`ResultGate`, and every other cross-pair are noncanonical and rejected
before public projection or durable acknowledgement.

Internal `UiActionV2` never places a capability in a URL. Every open variant
targets `Approval8766`, where approvald alone owns the WebAuthn ceremony.
`OpenIngress`, `OpenApproval`, and `OpenAgent` respectively fix the
post-authentication destination to `Ingress8767`, local `Approval8766`, and
`Agent8768`; neither caller nor browser supplies either mapping. Its random
purpose-specific `*UiAuthenticationTransferCapabilityV2` is delivered only
as a one-use browser POST body to approvald and is not decodable as either of
the other two transfer types.

`JarvisBootstrapUrlV2` is the separate non-secret array
`[FixedOriginV2::Jarvis8765, BootstrapKindV2,
JarvisBootstrapSelectorV2]`. Its formatter emits exactly
`http://localhost:8765/v2/bootstrap/<fixed-kind>/<base64url(selector)>`.
No JARVIS-visible URL contains a `TaskHandleV2`, capability,
expiry, query, fragment, userinfo, alternate host, percent encoding, redirect
target, or caller-controlled path.

The selector resolves only inside agentd to a hashed, expiring, current
preparation record. A GET returns fixed no-content HTML. A same-origin POST
atomically consumes the selector and may mint one
`KernelIngressBootstrapTransferCapabilityV2`, placed only in a browser form
POST body to ingressd. That transfer authorizes only creation of a fixed
pre-authentication page; it cannot read or write content. The purpose-bound
WebAuthn ceremony itself is owned and served by approvald at 8766. No input,
approval-derived display, or `AgentViewV2` is available until the exact
settlement is consumed and kerneld authorizes the destination origin.

```text
JarvisBootstrapSelectorV2 =
  HMAC-SHA-256(
    agentd_boot_selector_key,
    "SAVANA_JARVIS_BOOTSTRAP_SELECTOR_PRF_V2\0" ||
    canonical_cbor([
      installation_id,
      current_agentd_boot_id,
      durable_task_id,
      public_state_revision,
      BootstrapKindV2
    ]))
```

`agentd_boot_selector_key` is a distinct CSPRNG-generated locked-memory key,
never persisted or shared with replay/transport keys, and is destroyed at
agentd restart. The exact tuple has at most one live hashed selector row;
tag-10 replay and tag-11 status derive the same bytes rather than storing
plaintext or minting again. Consuming/tombstoning a selector atomically
advances the bootstrap/public-state revision or makes its kind unavailable,
so the consumed tuple can never produce live authority again.

## 4. Compiled ceilings

`HardLimitsV2::COMPILED` fixes:

```text
application record plaintext                   8 MiB
application record ciphertext                  8 MiB + 16-byte AEAD tag
canonical clear record header                   512 bytes
handshake CBOR body                             16 KiB
records / authenticated connection              3 total:
                                                  one server acceptance,
                                                  one client request,
                                                  one server response
input chunk                                    256 KiB
raw fetched result bytes                        8 MiB - 512 bytes
encoded AgentView response                      8 MiB - 512 bytes
sealed execution plaintext                      7 MiB
sealed execution HPKE ciphertext                7 MiB + 16-byte AEAD tag
encrypted journal record ciphertext             9 MiB
source bytes / input session                    32 MiB
extracted Unicode scalar values / session       1,000,000
pages / session                                 2,048
Unicode scalar values / page                    50,000
parser/OCR page pixels                          100,000,000
kernel value depth                              16
kernel value nodes                              65,536
kernel value encoded bytes                      8 MiB
prompt value handles                            256
derive input handles                            256
named arguments                                 256
internal validators / evaluation                32
root evidence digests / value                   64
ontology AST depth                              8
ontology AST nodes                              256
ontology All/Any children                       32
projection AST depth                            8
projection AST nodes                            256
plan steps                                      256
active tool descriptors / run                   4,096
action intents / run                            4,096
live runs / authenticated agent                 512
live values and handles / agent                 65,536
pending ingress sessions / ingress service      512
pending approvals / service                     4,096
live dispatches / executor                      1,024
request replay records / boot/client            65,536
browser mutation replay rows / boot/origin      65,536
durable PrepareIngress replay rows / principal  65,536
replay capsule plaintext                         8 MiB
replay capsule ciphertext                        8 MiB + 16-byte AEAD tag
action-intent emission records / run              4,096
action-state emission records / run              28,672
execution-document emission records / run         4,096
browser object-ref commitments / response         4,096
live parser extraction jobs / ingress service       512
live connector codec workers / execd               1,024
codec job records / execution nonce                   16
durable unresolved dispatch records             65,536
retained retired durable key epochs / family     4
```

Compiled maximum lifetimes:

```text
browser/ingress grant              15 minutes
receiving input                    15 minutes
awaiting input approval            15 minutes
planner ticket                      5 minutes
tool-call decision/approval        15 minutes
execution ticket                   15 minutes
run                                24 hours
task logical lifetime              24 hours
task query tombstone retention     30 days after logical expiry
unacknowledged result journal      30 days
durable reconciliation evidence    30 days
action/replay tombstone            max(run expiry, receipt expiry,
                                      recovery expiry)
```

The active signed resource profile may lower, but never raise, a compiled
ceiling. Decode, admission, allocation, execution, persistence, and response
encoding independently enforce the effective value.

## 5. Endpoint operation surfaces

### 5.1 JARVIS to agentd control

| Tag | Operation | Class |
|---:|---|---|
| 0 | `Health` | Query |
| 10 | `PrepareIngress` | IdempotentMutation |
| 11 | `GetTaskStatus` | Query |
| 12 | `CancelTask` | OneWayMutation |

```rust
struct AgentControlHealthRequestV2;

struct AgentControlHealthResponseV2 {
    state: PublicServiceStateV2,
}

struct PrepareIngressRequestV2 {
    client_request_nonce: Nonce32,
}

struct PrepareIngressResponseV2 {
    task: TaskHandleV2,
    bootstrap: JarvisBootstrapActionV2,
}

struct GetTaskStatusRequestV2 {
    task: TaskHandleV2,
}

struct GetTaskStatusResponseV2 {
    status: PublicTaskStatusV2,
}

struct CancelTaskRequestV2 {
    task: TaskHandleV2,
}

struct CancelTaskResponseV2 {
    status: PublicTaskStatusV2,
}

enum PublicTaskStatusV2 {
    AwaitingUiAuthentication {
        bootstrap: Option<JarvisBootstrapActionV2>,
    },
    AwaitingInput,
    Processing,
    AwaitingIngressApproval,
    Ready {
        bootstrap: Option<JarvisBootstrapActionV2>,
    },
    Running,
    Dispatching,
    Succeeded,
    EffectSucceededOutputQuarantined {
        class: PublicFailureClassV2,
    },
    PolicyDenied { class: PublicFailureClassV2 },
    FailedNoEffect { class: PublicFailureClassV2 },
    Indeterminate,
    Cancelled,
    Expired,
}

enum JarvisBootstrapActionV2 {
    None,
    OpenIngress {
        url: JarvisBootstrapUrlV2,
    },
    OpenApproval {
        url: JarvisBootstrapUrlV2,
    },
    OpenAgent {
        url: JarvisBootstrapUrlV2,
    },
}
```

`OpenIngress`, `OpenApproval`, and `OpenAgent` require URL bootstrap kinds
`Ingress`, `Approval`, and `Agent`, respectively; any cross-pair is
noncanonical. `Some(JarvisBootstrapActionV2::None)` is noncanonical and
rejected. No
response in this section contains a free boolean, integer, text, timestamp,
nonce, digest, content field, or any handle other than `TaskHandleV2`.
Response types contain no conversation, action, execution, release, recovery,
kernel run/value/vault, planner/tool, destination, approval, producer, or
content field.

`TaskHandleV2` is the sole boot-independent public handle. Its origin tuple
is:

```rust
struct TaskOriginBootV2 {
    machine_boot_id: BootIdV2,
    jarvis_control_client_boot_id: BootIdV2,
    agentd_server_boot_id: BootIdV2,
    kerneld_server_boot_id: BootIdV2,
}
```

The handle is a random 32-byte value stored hashed by agentd and its typed
resolver row binds exactly:

```text
installation_id
jarvis_principal: JarvisPrincipalIdV2
jarvis_os_peer_class: JarvisOsPeerClassV2
durable_task_id
handle_type = TaskHandleV2
origin_boots: TaskOriginBootV2
creating_manifest_digest
creating_deployment_generation
protocol_abi_digest
task_logical_expires_at
query_tombstone_retain_until
```

The handle's two time fields must equal the signed correlation's
`task_logical_expires_at` and `status_retain_until`, respectively; agentd
cannot shorten, extend, or reinterpret either value.

After a manifest change, agentd may read an existing handle resolver only
when the active manifest's exact `PersistentStoreCompatibilityV2` entry for
the agentd task-resolver store names that `ClosedStoreIdV2`, its desired
reader range contains the creating schema epoch, and its migration digest,
post-migration digest rule, and validator artifact all verify. Kerneld
operation 41 independently requires the corresponding exact task/correlation
store entry, reader range, migration/validator result, and retained
correlation verification key. `PersistentStoreCompatibilityV2` is a complete
store declaration, not a directional cross-manifest edge. Both reads must
accept the same creating manifest/generation and signed correlation; one
daemon's store declaration cannot authorize the other. Missing, wildcard,
wrong-store, out-of-range, schema-only inferred, or mismatched declarations
make the handle `InvalidReference` and never reconstruct a resolver.

Every `GetTaskStatus` reauthenticates the JARVIS control connection and
rechecks installation, enrolled JARVIS principal, OS peer class, durable task,
type, logical expiry, and tombstone retention bound before lookup. At
`task_logical_expires_at` the task becomes `Expired`, no mutation or content
read is authorized, and that closed status remains queryable through
`query_tombstone_retain_until`; after the retention bound the only result is
`InvalidReference`. In the exact four-part creation origin, the exact
operation may additionally apply its own authorization rule. After any of
the machine, JARVIS control client, agentd server, or kerneld server boot IDs
changes, `GetTaskStatus` is the only accepted operation; the
handle cannot authorize cancellation, input, session claim, planner work,
approval, dispatch, release, or content access.

`CancelTask` succeeds only when all four fields of `TaskOriginBootV2` still
match their freshly authenticated/current values and the shared task/effect
lock proves that no effect or release may have started. Otherwise it returns
`CancellationTooLate`.

`JarvisBootstrapUrlV2` contains only fixed `Jarvis8765`, a closed bootstrap
kind, and an independent no-content `JarvisBootstrapSelectorV2`; it never
contains `TaskHandleV2`. Resolving it returns only fixed bootstrap HTML.
Consuming it may start the corresponding purpose-bound UI-authentication flow
through a one-use browser POST transfer, never content authority.

### 5.2 agentd to kerneld

| Tag | Operation | Class |
|---:|---|---|
| 0 | `Health` | Query |
| 20 | `ClaimAgentSession` | SensitiveOneWayMutation |
| 21 | `PrepareFollowupIngress` | IdempotentMutation |
| 22 | `GetAgentSessionStatus` | Query |
| 23 | `PreparePlannerCall` | SensitiveIdempotentMutation |
| 24 | `CommitPlannerValue` | SensitiveIdempotentMutation |
| 25 | `DeriveValue` | IdempotentMutation |
| 26 | `ProposeToolCall` | IdempotentMutation |
| 27 | `EvaluateToolCall` | IdempotentMutation |
| 28 | `AuthorizeToolCall` | SensitiveOneWayMutation |
| 29 | `DispatchExecution` | SensitiveOneWayMutation |
| 30 | `GetExecutionStatus` | Query |
| 31 | `ReadAgentView` | `SensitiveIdempotentMutation` |
| 32 | `PrepareRelease` | SensitiveIdempotentMutation |
| 33 | `AuthorizeRelease` | SensitiveOneWayMutation |
| 34 | `DispatchRelease` | SensitiveOneWayMutation |
| 35 | `GetReleaseStatus` | Query |
| 36 | `RevokeVault` | OneWayMutation |
| 37 | `CloseAgentSession` | OneWayMutation |
| 38 | `PrepareNewIngress` | IdempotentMutation |
| 39 | `PrepareAgentUiAuthentication` | SensitiveIdempotentMutation |
| 40 | `AuthenticateAgentUi` | SensitiveOneWayMutation |
| 41 | `GetKernelTaskStatus` | Query |
| 42 | `CancelKernelTask` | OneWayMutation |
| 43 | `ResumeCommittedAgentAuthentication` | SensitiveIdempotentMutation |

Key DTOs:

```rust
enum UiActionV2 {
    None,
    OpenIngress {
        authentication_origin: FixedOriginV2,
        return_origin: FixedOriginV2,
        transfer: IngressUiAuthenticationTransferCapabilityV2,
        expires_at: UnixMillis,
    },
    OpenApproval {
        authentication_origin: FixedOriginV2,
        return_origin: FixedOriginV2,
        transfer: ApprovalDisplayAuthenticationTransferCapabilityV2,
        expires_at: UnixMillis,
    },
    OpenAgent {
        authentication_origin: FixedOriginV2,
        return_origin: FixedOriginV2,
        transfer: AgentUiAuthenticationTransferCapabilityV2,
        expires_at: UnixMillis,
    },
}

struct KernelAgentHealthRequestV2;

struct KernelAgentHealthResponseV2 {
    ready: bool,
    state: PublicServiceStateV2,
}

struct UnsignedDurableTaskCorrelationV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    durable_task_id: DurableTaskIdV2,
    agentd_identity: ServiceIdentityV2,
    agentd_kernel_client_boot_id: BootIdV2,
    kerneld_server_boot_id: BootIdV2,
    machine_boot_id: BootIdV2,
    issued_at: UnixMillis,
    task_logical_expires_at: UnixMillis,
    status_retain_until: UnixMillis,
}

enum KernelTaskStatusV2 {
    AwaitingUiAuthentication = 1,
    AwaitingInput = 2,
    Processing = 3,
    AwaitingIngressApproval = 4,
    Ready = 5,
    Running = 6,
    Dispatching = 7,
    Succeeded = 8,
    EffectSucceededOutputQuarantined {
        class: PublicFailureClassV2,
    } = 9,
    PolicyDenied {
        class: PublicFailureClassV2,
    } = 10,
    FailedNoEffect {
        class: PublicFailureClassV2,
    } = 11,
    Indeterminate = 12,
    Cancelled = 13,
    Expired = 14,
}

struct ClaimAgentSessionRequestV2 {
    authorization: AgentUiAuthorizationHandleV2,
}

struct ClaimAgentSessionResponseV2 {
    session: AgentSessionHandleV2,
    run: RunHandleV2,
    run_revision: RunRevisionObservationV2,
    initial_value: ValueHandleV2,
    initial_document: MaskedDocumentHandleV2,
    active_tools: BoundedVec<ActiveToolViewV2, 4096>,
}

struct PrepareNewIngressRequestV2 {
    agent_task_nonce: Nonce32,
    client_request_nonce: Nonce32,
}

enum PrepareNewIngressResponseV2 {
    Prepared {
        preparation: NewTaskPreparationHandleV2,
        correlation: SignedDurableTaskCorrelationV2,
        ingress_transfer: KernelIngressBootstrapTransferCapabilityV2,
    } = 1,
    Reconciled {
        correlation: SignedDurableTaskCorrelationV2,
        current: KernelTaskStatusV2,
    } = 2,
}

struct PrepareFollowupIngressRequestV2 {
    session: AgentSessionHandleV2,
    run: RunHandleV2,
    client_request_nonce: Nonce32,
}

struct PrepareFollowupIngressResponseV2 {
    correlation: SignedDurableTaskCorrelationV2,
    input_transfer: KernelIngressBootstrapTransferCapabilityV2,
}

struct GetAgentSessionStatusRequestV2 {
    session: AgentSessionHandleV2,
}

struct GetAgentSessionStatusResponseV2 {
    status: AgentSessionStatusV2,
    run_revision: Option<RunRevisionObservationV2>,
}

struct PrepareAgentUiAuthenticationRequestV2 {
    preparation: NewTaskPreparationHandleV2,
}

struct PrepareAgentUiAuthenticationResponseV2 {
    authentication_preparation: AgentUiAuthenticationPreparationHandleV2,
    envelope: SignedUiAuthenticationEnvelopeV2,
}

struct AuthenticateAgentUiRequestV2 {
    authentication_preparation: AgentUiAuthenticationPreparationHandleV2,
    settlement: SignedUiAuthenticationSettlementV2,
}

struct AuthenticateAgentUiResponseV2 {
    authorization: AgentUiAuthorizationHandleV2,
}

struct GetKernelTaskStatusRequestV2 {
    correlation: SignedDurableTaskCorrelationV2,
}

struct GetKernelTaskStatusResponseV2 {
    status: KernelTaskStatusV2,
}

struct CancelKernelTaskRequestV2 {
    preparation: NewTaskPreparationHandleV2,
    correlation: SignedDurableTaskCorrelationV2,
}

struct CancelKernelTaskResponseV2 {
    status: KernelTaskStatusV2,
}

struct ResumeCommittedAgentAuthenticationRequestV2 {
    correlation: SignedDurableTaskCorrelationV2,
    client_request_nonce: Nonce32,
    prior_attempt_closure_proof:
        Option<SignedAgentAuthenticationAttemptClosureProofV2>,
}

enum ResumeCommittedAgentAuthenticationResponseV2 {
    Prepared {
        authentication_preparation: AgentUiAuthenticationPreparationHandleV2,
        envelope: SignedUiAuthenticationEnvelopeV2,
    } = 1,
    ClosureRequired {
        closure: SignedAgentAuthenticationClosureDescriptorV2,
    } = 2,
}

struct PreparePlannerCallRequestV2 {
    run: RunHandleV2,
    planner_route: PlannerRouteIdV2,
    prompt_values: BoundedVec<ValueHandleV2, 256>,
}

struct PreparePlannerCallResponseV2 {
    ticket: PlannerTicketHandleV2,
    envelope: PlannerEnvelopeV2,
    envelope_digest: Digest32,
    expires_at: UnixMillis,
}

struct CommitPlannerValueRequestV2 {
    run: RunHandleV2,
    ticket: PlannerTicketHandleV2,
    plan: PlannerPlanV2,
}

struct CommitPlannerValueResponseV2 {
    value: ValueHandleV2,
    value_digest: Digest32,
    plan_revision_digest: PlanRevisionDigestV2,
    steps: BoundedVec<PlanStepHandleV2, 256>,
}

struct DeriveValueRequestV2 {
    run: RunHandleV2,
    operation: DeriveOperationV2,
    inputs: BoundedVec<ValueHandleV2, 256>,
}

struct DeriveValueResponseV2 {
    value: ValueHandleV2,
    value_digest: Digest32,
}

struct NamedArgumentValueBindingV2 {
    name: ArgumentNameV2,
    value: ValueHandleV2,
}

struct ProposeToolCallRequestV2 {
    step: PlanStepHandleV2,
    tool: ToolHandleV2,
    arguments: BoundedVec<NamedArgumentValueBindingV2, 256>,
}

struct ProposeToolCallResponseV2 {
    intent: ActionIntentHandleV2,
    current: ActionIntentCurrentStateV2,
}

enum ActionIntentCurrentStateV2 {
    Proposed {
        pending: PendingToolCallHandleV2,
    } = 1,
    Evaluating {
        pending: PendingToolCallHandleV2,
    } = 2,
    Denied {
        code: PublicStableCodeV2,
        trace: PublicDecisionTraceV2,
    } = 3,
    AwaitingApproval {
        pending: PendingToolCallHandleV2,
    } = 4,
    Authorized {
        ticket: ExecutionTicketHandleV2,
    } = 5,
    Dispatched {
        execution: ExecutionHandleV2,
        phase: ActionIntentDispatchPhaseV2,
    } = 6,
    Terminal {
        execution: ExecutionHandleV2,
        summary: ActionIntentTerminalSummaryV2,
    } = 7,
}

enum ActionIntentDispatchPhaseV2 {
    Prepared = 1,
    Dispatching = 2,
    CompletionCommitPending = 3,
}

enum ActionIntentTerminalSummaryV2 {
    Succeeded = 1,
    EffectSucceededOutputQuarantined {
        class: PublicFailureClassV2,
    } = 2,
    FailedNoEffect {
        class: PublicFailureClassV2,
    } = 3,
    Indeterminate = 4,
}

struct EvaluateToolCallRequestV2 {
    pending: PendingToolCallHandleV2,
}

enum EvaluateToolCallResponseV2 {
    Denied {
        code: PublicStableCodeV2,
        trace: PublicDecisionTraceV2,
    },
    NeedsApproval {
        approval: ToolKernelApprovalHandleV2,
        envelope: SignedApprovalEnvelopeV2,
        display_authentication: SignedUiAuthenticationEnvelopeV2,
        trace: PublicDecisionTraceV2,
    },
    Allowed {
        ticket: ExecutionTicketHandleV2,
        trace: PublicDecisionTraceV2,
    },
}

struct AuthorizeToolCallRequestV2 {
    pending: PendingToolCallHandleV2,
    approval: ToolKernelApprovalHandleV2,
    receipt: SignedApprovalSettlementV2,
}

struct AuthorizeToolCallResponseV2 {
    ticket: ExecutionTicketHandleV2,
}

struct DispatchExecutionRequestV2 {
    ticket: ExecutionTicketHandleV2,
}

struct DispatchExecutionResponseV2 {
    execution: ExecutionHandleV2,
    status: PublicDispatchAcceptedStateV2,
}

enum PublicDispatchAcceptedStateV2 {
    Prepared = 1,
    Dispatching = 2,
}

enum ExecutionStatusTargetV2 {
    Intent(ActionIntentHandleV2),
    Ticket(ExecutionTicketHandleV2),
    Execution(ExecutionHandleV2),
}

enum PublicExecutionStatusV2 {
    Prepared,
    Dispatching,
    ResultGatePending,
    Succeeded { completion: PublicDispatchCompletionV2 },
    EffectSucceededOutputQuarantined { class: PublicFailureClassV2 },
    FailedNoEffect { class: PublicFailureClassV2 },
    Indeterminate,
}

enum PublicDispatchCompletionV2 {
    ToolExecution {
        document: MaskedDocumentHandleV2,
    } = 1,
    FinalRelease = 2,
}

struct GetExecutionStatusRequestV2 {
    target: ExecutionStatusTargetV2,
}

struct GetExecutionStatusResponseV2 {
    status: PublicExecutionStatusV2,
}

struct ReadAgentViewRequestV2 {
    document: MaskedDocumentHandleV2,
    cursor: Option<KernelAgentViewCursorV2>,
    maximum_encoded_bytes: u32,
    client_request_nonce: Nonce32,
}

struct ReadAgentViewResponseV2 {
    view: AgentViewV2,
    next: Option<KernelAgentViewCursorV2>,
}

struct PrepareReleaseRequestV2 {
    document: MaskedDocumentHandleV2,
    evidence: BoundedVec<ValueHandleV2, 256>,
    executor: ExecutorIdentityV2,
    destination_projection: ProjectionIdV2,
    display_projection: DisplayProjectionIdV2,
}

struct PrepareReleaseResponseV2 {
    pending: PendingReleaseHandleV2,
    approval: ReleaseKernelApprovalHandleV2,
    envelope: SignedApprovalEnvelopeV2,
    display_authentication: SignedUiAuthenticationEnvelopeV2,
}

struct AuthorizeReleaseRequestV2 {
    pending: PendingReleaseHandleV2,
    approval: ReleaseKernelApprovalHandleV2,
    settlement: SignedApprovalSettlementV2,
}

struct AuthorizeReleaseResponseV2 {
    ticket: ReleaseTicketHandleV2,
}

struct DispatchReleaseRequestV2 {
    ticket: ReleaseTicketHandleV2,
}

struct DispatchReleaseResponseV2 {
    release: ReleaseHandleV2,
    status: PublicDispatchAcceptedStateV2,
}

enum ReleaseStatusTargetV2 {
    Pending(PendingReleaseHandleV2),
    Ticket(ReleaseTicketHandleV2),
    Release(ReleaseHandleV2),
}

struct GetReleaseStatusRequestV2 {
    target: ReleaseStatusTargetV2,
}

struct GetReleaseStatusResponseV2 {
    status: PublicExecutionStatusV2,
}

struct RevokeVaultRequestV2 {
    document: MaskedDocumentHandleV2,
}

struct RevokeVaultResponseV2 {
    state: VaultPublicStateV2,
}

struct CloseAgentSessionRequestV2 {
    session: AgentSessionHandleV2,
}

struct CloseAgentSessionResponseV2 {
    state: AgentSessionStatusV2,
}
```

`SignedDurableTaskCorrelationV2` is section 3.1's signed-object encoding of
`UnsignedDurableTaskCorrelationV2`. Its signature input is:

```text
"SAVANA_DURABLE_TASK_CORRELATION_V2\0" ||
SHA-256(payload_bstr)
```

Only the active kerneld task-correlation key may sign it. It is a
non-capability, non-bearer status correlation accepted only on the
authenticated `AgentKernel` role from the exact bound agentd identity.
The active security-state manifest binds that dedicated Ed25519 key ID and
its bounded retired verification set; it is distinct from handshake,
approval/UI envelope, execution-envelope, and approvald settlement keys.
Operation 41 is its sole cross-boot query resolver and returns only
`KernelTaskStatusV2`. Operation 43 is the sole, narrower cross-boot mutation
that may use it only as a typed durable-task lookup exception under the
recovery predicate below; this does not make the correlation a general
mutation resolver. No other role, mutation,
browser route, semantic digest, or persistent kernel object accepts a public
`TaskHandleV2`.

Operation 41 verifies the signature, bound agentd identity, installation,
manifest lineage, durable task, and `status_retain_until` before lookup. At
`task_logical_expires_at` it returns only `Expired` and authorizes no content
or mutation; through `status_retain_until` that tombstone remains queryable.
After the retain bound, the correlation and the corresponding public mapping
resolve only to `InvalidReference`.

Operation 43 is the sole recovery mutation for a durable input that reached
`CommittedUnclaimed` before agent UI authentication or claim completed. The
signed correlation is lookup evidence, never authority by itself. Over the
freshly authenticated `AgentKernel` connection kerneld requires:

- the exact current agentd service identity and installation bound by the
  correlation;
- the durable task to be exactly `CommittedUnclaimed`, or
  `AgentAuthPending` only on one of the closed recovery branches below;
- the stored authenticated principal and the immutable
  `UnredeemableAgentClaimCommitmentV2` to match the task;
- the request digest and `client_request_nonce` to select one exact replay
  row before any recovery transition;
- the active manifest to equal the committed manifest, or the exact
  deployment `AgentClaimCompatibilityV2` component in the signed destination
  manifest to authorize that one named, directional, protocol-ABI-identical
  old-manifest/new-manifest pair.

The request union is closed by state and replay history:

| Main state / request | Canonical result |
|---|---|
| `CommittedUnclaimed` + `prior_attempt_closure_proof=None` | first `Prepared`; transition to `AgentAuthPending` |
| `CommittedUnclaimed` + `Some` | reject before lookup/mint |
| `AgentAuthPending` + exact original same-boot replay | existing `Prepared` from the verified replay capsule |
| `AgentAuthPending` + fresh `None`, old attempt still live in the current boot | `StateConflict` |
| `AgentAuthPending` + fresh `None`, originating boot changed or attempt expired/unavailable | `ClosureRequired` containing the one stored signed closure descriptor |
| `AgentAuthPending` + fresh `Some(safe closure proof)` | one replacement `Prepared`; state remains `AgentAuthPending` |
| `AgentAuthPending` + fresh `Some(unsafe, stale, or mismatched proof)` | `RestartInvalidated` transaction, no preparation |

Any other state/option/replay combination is rejected before minting. An
exact replay of `ClosureRequired` returns the same descriptor bytes; a
different request under its replay key is `IdempotencyConflict`.

In the original creation boot, normal operation 39 may perform the same first
`CommittedUnclaimed → AgentAuthPending` transition using its
`NewTaskPreparationHandleV2`; recovery operation 43 may perform that first
transition using the signed-correlation lookup exception. Both create the
same single `AgentAuthenticationRecoveryRecordV2` shape. Neither operation
may create a second live record.

Under the durable-task and claim locks, the operation creates only a fresh
same-boot `AgentUiAuthenticationPreparationHandleV2` and a fresh
`AgentContent` `SignedUiAuthenticationEnvelopeV2`, writes the exact
`AgentAuthenticationRecoveryRecordV2`, signs and stores the corresponding
content-free `SignedAgentAuthenticationClosureDescriptorV2`, and advances the
primary input state from `CommittedUnclaimed` to `AgentAuthPending` in the
same transaction. The descriptor binds the digest of that now-durable
recovery record and has no resolver authority. The transition cannot read input,
materialize a value, mint an agent session, redeem the claim commitment,
or create an approval/effect/release. Only a later
valid operation 40 settlement may create
`AgentUiAuthorizationHandleV2` and advance the recovery phase to
`AuthenticatedAwaitingClaim`; operation 20 then atomically redeems the stored
claim commitment, sets both recovery phase `Claimed` and primary
`AgentClaimed`, and returns the session/run handles.

At every kerneld boot, a bounded scan indexes all `CommittedUnclaimed` and
`AgentAuthPending` records by durable task and signed-correlation digest
before AgentKernel is served. Exact authenticated same-boot replay of
operation 43 returns the same preparation/envelope through section 10's
role-specific capsule; a changed correlation, principal, peer, installation,
or commitment conflicts. A different nonce during the same boot while the
primary state is `AgentAuthPending` and the current attempt is live returns
`StateConflict` and never mints a second preparation.

Across a boot change or expiry, `AgentAuthPending` never moves backward to
`CommittedUnclaimed`. A proof-free fresh operation 43 may return only
`ClosureRequired`; it neither terminalizes the attempt nor mints a
replacement. Agentd must pass that exact descriptor to AgentApproval
operation 24. Under approvald's one complete-index lock, operation 24 either
(a) proves no registration and atomically writes the permanent
envelope/attempt denylist tombstone, (b) terminalizes every registered
record, ceremony, settlement, and transfer and writes that tombstone, or
(c) reports the exact observed/indeterminate unsafe evidence. Operation 22
checks the denylist before registration and can never resurrect the old
envelope.

Approvald returns `SignedAgentAuthenticationAttemptClosureProofV2`.
Kerneld verifies the signer role/key epoch, descriptor digest,
attempt-manifest/closure-manifest matrix, compatibility and persistent-store
read edges, principal/task/correlation/claim/attempt/envelope/recovery-record
equality, complete-index generation, authenticated journal head, descendant
states, denylist tombstone, and proof lifetime. Only
`NeverRegisteredDenylisted` and `RegisteredInvalidatedUnredeemed` authorize
replacement. Under the durable-task, recovery-record, preparation, envelope,
replay, and claim locks, one transaction tombstones the old preparation,
envelope, authorization, and replay capability material before it creates the
new current-boot preparation/envelope/recovery record and closure descriptor.
The primary state remains `AgentAuthPending` throughout. Local absence of an
agentd or kerneld row, approvald availability, or a transport error is never
evidence of non-redemption.

The only valid primary/recovery-phase pairs are
`AgentAuthPending/Prepared`,
`AgentAuthPending/AuthenticatedAwaitingClaim`,
`AgentClaimed/Claimed`, and
`RestartInvalidated/RestartInvalidated`; disagreement is fail-stop.
The authorization-state matrix is also exact:

| Recovery phase | Authorization state |
|---|---|
| `Prepared` | `NotCreated` |
| `AuthenticatedAwaitingClaim` | `LiveAwaitingClaim` |
| `Claimed` | `ConsumedByClaim`, binding the same claim transaction |
| `RestartInvalidated` | `NotCreated` if none was ever issued, otherwise `TombstonedOnRestart` |

A missing, extra, live-after-terminal, consumed-before-claim, or
hash/transaction/tombstone mismatch is corruption and never causes a handle
to be recreated.

An expired task becomes internal `Expired`. A missing/corrupt commitment,
missing/expired/wrong-signer closure proof,
`SettlementOrTransferObserved`, `Indeterminate`, unprovable
settlement/authorization consumption, incompatible manifest/store edge, or
otherwise impossible continuation atomically becomes internal
`RestartInvalidated`, recovery phase `RestartInvalidated`, and a durable
`RestartInvalidatedRecordV2` with exactly one committed disposition. The
transaction retains or destroys the exact unclaimed vault only according to
the verified signed retention policy and binds that claim/vault/decision in
the disposition. It never uses `PreCommitStagingCleared` after
`CommittedUnclaimed`. Its JARVIS projection is exactly
`PublicTaskStatusV2::FailedNoEffect { class: Infrastructure }`, never a
publicly invented state with the internal name. Restart destroys or
tombstones the old preparation only through the verified proof or the
fail-closed committed-disposition transaction above. A new operation 43 is
permitted from `CommittedUnclaimed` for the first attempt, or from
`AgentAuthPending` only through the closure/replacement flow; there is no
rollback edge in the primary state machine.
`TaskHandleV2` remains cross-boot query-only and cannot select either branch.

kerneld owns the durable task and signed correlation; agentd alone generates,
hashes, stores, and resolves the public `TaskHandleV2` and
`JarvisBootstrapSelectorV2`. `NewTaskPreparationHandleV2` is a same-boot
kernel capability accepted only by `PrepareAgentUiAuthentication` and
`CancelKernelTask`; follow-up ingress exposes no preparation handle. Agentd
atomically binds its public task handle and selector to the new-task
preparation/correlation result before replying to JARVIS.

`CancelKernelTask` requires both that same-boot preparation and the exact
correlation. Under the durable task/effect locks it succeeds only before every
effect and release reaches `DispatchPrepared`; it atomically cancels task
state and clears unconsumed staging, approval reservations, and tickets.
Restart, stale preparation, dispatch preparation, or any possibly sent byte
returns `CancellationTooLate` without changing state. JARVIS `CancelTask`
does not form a distributed transaction with kerneld: only the kernel
mutation above is atomic. Agentd durably records the authenticated kernel
response and replay digest before replying to JARVIS. If agentd crashes
between those steps, it reconciles with the stored signed correlation through
operation 41 and makes an exact replay return the same closed result; no
two-phase-commit or cross-daemon atomicity is claimed.

`AgentViewV2` is data-bearing and available only on this endpoint. It is never
accepted by a planner or executor operation.

Release records assign one typed `DurableReleaseIdV2` and store the exact
`FinalReleaseSemanticBindingV2`, thereby binding the vault internal identity
and digest, release-payload digest, evidence, token set, destination,
destination/display projections and outputs, executor identity, the distinct
release-quota subject, and exact signed settlement. It contains no tool
attempt kind. The same binding becomes
`DispatchSubjectV2::FinalRelease` all the way through dispatch, WAL, execd,
receipt, status, quota, and recovery. `DispatchRelease` returns only a
boot-bound release handle and `PublicDispatchAcceptedStateV2`, restricted to
`Prepared` or `Dispatching`; it returns no
plaintext and no boot-independent recovery capability.

`PrepareRelease` and `RevokeVault` accept only an already issued
`MaskedDocumentHandleV2`; kerneld resolves its immutable backing segment
under the document/vault lock. No `VaultSegmentHandleV2` or browser vault
handle exists, so a caller cannot substitute or enumerate an internal
segment.

`NamedArgumentValueBindingV2` entries MUST be strictly increasing by canonical
`ArgumentNameV2` bytes, contain no duplicate or unknown name, and match the
selected descriptor's required/optional argument set and value schema.
`ProposeToolCall`, not planner commit, is the only transition that chooses one
exact descriptor and arguments and creates an action intent.

`PrepareFollowupIngress` accepts no revision, digest, sequence, or CAS token
from agentd. After resolving the exact live session/run pair, kerneld takes
the run lock, reads the server-owned `RunRevisionV2`, and snapshots its digest
into the pending ingress subject. `RunRevisionObservationV2` in claim/status
responses is a non-authorizing freshness observation for agentd's internal
view; no operation accepts it back as authority, and no 8765 or 8768 response
contains it or any run-revision digest.

For `PrepareNewIngress`, agentd supplies only fresh request-correlation nonces.
kerneld generates `DurableTaskIdV2`, its internal preparation, signed
correlation, and ingress-only origin transfer in one transaction. It never
generates, stores, receives, or returns a public `TaskHandleV2` or JARVIS
bootstrap. Neither caller nonce is used as, transformed into, or accepted in
place of the durable task ID.

Tag 10 and operation 38 form a durable, idempotent saga rather than a
cross-daemon transaction:

```rust
enum AgentdPrepareIngressPhaseV2 {
    Reserved = 1,
    KernelCommitted = 2,
    Published = 3,
    FailedNoEffect = 4,
}

struct AgentdTaskOriginPrefixV2 {
    machine_boot_id: BootIdV2,
    jarvis_control_client_boot_id: BootIdV2,
    agentd_server_boot_id: BootIdV2,
}

struct AgentdPrepareIngressRecordV2 {
    schema_version: u16,                 // exactly 2
    creating_manifest_digest: Digest32,
    protocol_abi_digest: Digest32,
    durable_prepare_ingress_key:
        DurablePrepareIngressKeyV2,
    original_jarvis_request_digest: Digest32,
    jarvis_control_transcript_digest: Digest32,
    origin_prefix: AgentdTaskOriginPrefixV2,
    stable_agent_task_nonce: Nonce32,
    stable_kernel_client_request_nonce: Nonce32,
    kernel_request_digest: Digest32,
    phase: AgentdPrepareIngressPhaseV2,
    durable_task_id: Option<DurableTaskIdV2>,
    signed_task_correlation:
        Option<SignedDurableTaskCorrelationV2>,
    signed_task_correlation_digest: Option<Digest32>,
    origin_boots: Option<TaskOriginBootV2>,
    task_handle_resolver_typed_hash: Option<Digest32>,
    durable_task_handle_capsule_digest: Option<Digest32>,
    created_at: UnixMillis,
    query_tombstone_retain_until: Option<UnixMillis>,
    record_digest: Digest32,
}

struct KernelAgentTaskCreationKeyV2 {
    installation_id: Digest32,
    agentd_logical_identity: ServiceIdentityV2,
    agent_task_nonce: Nonce32,
}

struct KernelAgentTaskCreationRecordV2 {
    schema_version: u16,                 // exactly 2
    creating_manifest_digest: Digest32,
    protocol_abi_digest: Digest32,
    key: KernelAgentTaskCreationKeyV2,
    exact_request_digest: Digest32,
    durable_task_id: DurableTaskIdV2,
    signed_task_correlation: SignedDurableTaskCorrelationV2,
    signed_task_correlation_digest: Digest32,
    current_task_state_revision: u64,
    current_preparation_boot_id: Option<BootIdV2>,
    current_preparation_resolver_typed_hash: Option<Digest32>,
    current_ingress_transfer_resolver_typed_hash: Option<Digest32>,
    bootstrap_material_state: KernelIngressBootstrapMaterialStateV2,
    status_retain_until: UnixMillis,
    record_digest: Digest32,
}

enum KernelIngressBootstrapMaterialStateV2 {
    NotIssued = 1,
    IssuedCurrentBoot = 2,
    ConsumedOrStateAdvanced = 3,
    Tombstoned = 4,
}
```

```text
AgentdPrepareIngressRecordDigest =
  SHA-256("SAVANA_AGENTD_PREPARE_INGRESS_RECORD_V2\0" ||
          canonical_cbor(record excluding record_digest))

KernelAgentTaskCreationRecordDigest =
  SHA-256("SAVANA_KERNEL_AGENT_TASK_CREATION_RECORD_V2\0" ||
          canonical_cbor(record excluding record_digest))
```

The agentd option matrix is exact:

| Phase | origin prefix | task/correlation/digest | full origin boots | TaskHandle resolver/capsule | retain-until |
|---|---|---|---|---|---|
| `Reserved` | exact original three-part prefix | all `None` | `None` | both `None` | `None` |
| `KernelCommitted` | same prefix | all `Some` and mutually matching | `Some`, exact four-part origin | both `None` | `Some`, copied from correlation |
| `Published` | same prefix | all `Some` and mutually matching | same `Some` | both `Some` | same `Some` |
| `FailedNoEffect` | same prefix | all `None` | `None` | both `None` | `None` |

Every other `Some`/`None` combination is corrupt and fails stop. The kernel
bootstrap-material matrix is also exact:

| Material state | boot ID | preparation resolver | transfer resolver |
|---|---|---|---|
| `NotIssued` | `None` | `None` | `None` |
| `IssuedCurrentBoot` | current kerneld boot | `Some` | `Some` |
| `ConsumedOrStateAdvanced` | `None` | `None` | `None` |
| `Tombstoned` | `None` | `None` | `None` |

The latter state is derived and revalidated against canonical task state and
both resolver indexes under the task lock; conflicting redundant fields are
journal corruption, never a reason to mint.

Before calling operation 38, agentd commits `Reserved` with the exact durable
tag-10 key, authenticated local JARVIS transcript digest, typed
`AgentdTaskOriginPrefixV2`, both stable nonces, and both request digests.
The typed prefix, not the one-way transcript digest alone, preserves the
original machine, JARVIS control-client, and agentd server boots across a
crash. Kerneld never receives or trusts the JARVIS
principal, OS-peer class, durable tag-10 key, or JARVIS transcript; those stay
solely in the local agentd saga. It creates no
`TaskHandleV2` yet. `agent_task_nonce` and the signed correlation are
non-bearer correlation values: only the exact authenticated AgentKernel
logical identity may present/resolve the former at operation 38, and only
operations 41/43 may use the latter as specified above.

The signed correlation records only the machine boot, authenticated
agentd-as-AgentKernel-client boot, and kerneld server boot; it contains no
JARVIS principal, peer class, or control-client boot. After verifying the
correlation against the exact operation-38 transcript, agentd requires its
stored original `origin_prefix.machine_boot_id` to equal the correlation
machine boot and its stored original `origin_prefix.agentd_server_boot_id` to
equal the correlation's authenticated agentd client-process boot. It then
combines that immutable prefix with the correlation's kerneld server boot and
persists the resulting `TaskOriginBootV2`. It compares against the original
stored agentd boot, not the recovery process's current boot; therefore a
crash after kerneld commit cannot orphan the task. A handle published by a
later boot already fails the four-way same-origin mutation check and is
status-only. No daemon may copy a JARVIS-origin field into a kernel
correlation or infer one after a crash.

Kerneld maintains a durable semantic index on
`(installation_id, exact agentd logical identity, agent_task_nonce)`.
The first exact request atomically creates one durable task, correlation, and
index row. The same key and byte-exact request across either client or server
boot resolves that same task and correlation; a different request digest is
`IdempotencyConflict` and cannot allocate a task. This semantic index is
independent of the boot replay key.

If the task is still at the one state that permits ingress bootstrap,
operation 38 tombstones any old-boot unconsumed preparation/transfer under
the task lock, then returns or creates at most one current-kerneld-boot pair
for the exact task-state revision. If either material was consumed or task
state advanced, it returns `Reconciled { correlation, current }`; it never
recreates authority or moves state backward. Same-boot exact replay verifies
the current resolver commitments before returning `Prepared`.

After receiving either success, agentd durably writes `KernelCommitted` with
the exact durable task/correlation. In one final local transaction it then
generates the first random `TaskHandleV2`, inserts its typed resolver mapping,
seals `DurableTaskHandleEmission`, binds the durable replay row, and advances
to `Published`. Only after that transaction commits may tag 10 reply. A crash
before it leaves no public handle; recovery uses the stable op38 semantic key
and may safely perform this final transaction once. A crash after it is
replayed from the durable capsule and cannot mint a second handle.

Crash before operation 38 leaves `Reserved`; crash after kerneld commit but
before agentd observes it also leaves `Reserved`; crash while recording
`KernelCommitted`; crash before/after the atomic `Published` transaction; and
response loss after `Published` all converge to the same task, correlation,
and TaskHandle. `FailedNoEffect` is legal only when agentd durably proves the
operation-38 transport was never entered. Once a send may have occurred, the
saga must recover through kerneld's semantic index or fail stop; timeout,
connection loss, a missing/corrupt semantic index, a missing boot replay slot,
or local absence never proves no task was committed.

Cross-manifest saga or semantic-index reads are denied by default. They
require identical protocol ABI, exact unchanged agentd logical identity, and
the exact destination-manifest `PersistentStoreCompatibilityV2` entries for
both named stores, with desired reader ranges containing their creating
schema epochs and verified migration digests, post-migration digest rules, and
validator artifacts. These store declarations authorize reading existing
rows only and cannot authorize new task creation under old request bytes.
Missing, wrong-store, out-of-range, wildcard, or schema-only inferred
compatibility fails stop.

Agentd does not GC `Reserved` or `KernelCommitted` while kerneld could retain
the creation index; it reconciles them before serving tag 10. `Published`
survives through the exact `query_tombstone_retain_until`; kerneld retains its
creation row and correlation through `status_retain_until`.
`FailedNoEffect` retains its conflict tombstone through the original request
window. No step claims cross-daemon ACID: uniqueness comes from the two local
transactions plus kerneld's durable semantic index and bounded reconciliation.

### 5.3 ingressd to kerneld

| Tag | Operation | Class |
|---:|---|---|
| 0 | `Health` | Query |
| 40 | `BeginInput` | IdempotentMutation |
| 41 | `AppendInputChunk` | SensitiveIdempotentMutation |
| 42 | `FinalizeInput` | SensitiveIdempotentMutation |
| 43 | `CommitInputSettlement` | SensitiveOneWayMutation |
| 44 | `AbortInput` | OneWayMutation |
| 45 | `GetInputStatus` | Query |
| 46 | `PrepareIngressUiAuthentication` | SensitiveOneWayMutation |
| 47 | `AuthenticateIngressUi` | SensitiveOneWayMutation |
| 48 | `RegisterParserWorkerJob` | SensitiveIdempotentMutation |
| 49 | `AppendParserWorkerPageFrame` | SensitiveIdempotentMutation |
| 50 | `CommitParserWorkerResult` | SensitiveOneWayMutation |

```rust
struct KernelIngressHealthRequestV2;

struct KernelIngressHealthResponseV2 {
    ready: bool,
    state: PublicServiceStateV2,
}

struct PrepareIngressUiAuthenticationRequestV2 {
    transfer: KernelIngressBootstrapTransferCapabilityV2,
}

struct PrepareIngressUiAuthenticationResponseV2 {
    authentication_preparation: IngressUiAuthenticationPreparationHandleV2,
    envelope: SignedUiAuthenticationEnvelopeV2,
}

struct AuthenticateIngressUiRequestV2 {
    authentication_preparation: IngressUiAuthenticationPreparationHandleV2,
    settlement: SignedUiAuthenticationSettlementV2,
}

struct AuthenticateIngressUiResponseV2 {
    authorization: IngressUiAuthorizationHandleV2,
}

struct BeginInputRequestV2 {
    ui_authorization: IngressUiAuthorizationHandleV2,
    content_kind: ContentKindV2,
    declared_total_bytes: u64,
    declared_content_digest: Option<Digest32>,
}

enum ContentKindV2 {
    ChatText = 1,
    PlainText = 2,
    ParsedDocument = 3,
}

struct BeginInputResponseV2 {
    session: InputSessionHandleV2,
    writer: IngressWriteCapabilityV2,
    parser_job_session_binding_digest: Digest32,
    next_sequences: BoundedSortedVec<(InputChannelV2, u32), 3>,
}

enum InputChannelV2 {
    OriginalSource = 1,
    ExtractedPage = 2,
    ChatText = 3,
}

enum DirectInputChannelV2 {
    OriginalSource = 1,
    ChatText = 2,
}

struct AppendInputChunkRequestV2 {
    writer: IngressWriteCapabilityV2,
    channel: DirectInputChannelV2,
    sequence: u32,
    prior_cumulative_digest: Digest32,
    chunk: ZeroizingBytesV2,
    chunk_digest: Digest32,
    resulting_cumulative_digest: Digest32,
}

struct AppendInputChunkResponseV2 {
    channel: DirectInputChannelV2,
    acknowledged_sequence: u32,
    cumulative_digest: Digest32,
}

struct FinalizeInputRequestV2 {
    session: InputSessionHandleV2,
    channels: BoundedSortedVec<InputChannelCommitmentV2, 3>,
    source_provenance: InputSourceProvenanceV2,
}

struct InputChannelCommitmentV2 {
    channel: InputChannelV2,
    chunk_count: u32,
    final_sequence: u32,
    total_length: u64,
    final_cumulative_digest: Digest32,
}

struct FinalizeInputResponseV2 {
    pending: PendingIngressHandleV2,
    approval: IngressKernelApprovalHandleV2,
    envelope: SignedApprovalEnvelopeV2,
    display_authentication: SignedUiAuthenticationEnvelopeV2,
}

struct CommitInputSettlementRequestV2 {
    pending: PendingIngressHandleV2,
    approval: IngressKernelApprovalHandleV2,
    settlement: SignedApprovalSettlementV2,
}

struct CommitInputSettlementResponseV2 {
    state: InputPublicStateV2,
}

struct AbortInputRequestV2 {
    session: InputSessionHandleV2,
}

struct AbortInputResponseV2 {
    state: InputPublicStateV2,
}

enum InputStatusTargetV2 {
    Session(InputSessionHandleV2),
    Pending(PendingIngressHandleV2),
}

struct GetInputStatusRequestV2 {
    target: InputStatusTargetV2,
}

struct GetInputStatusResponseV2 {
    state: InputPublicStateV2,
}

struct RegisterParserWorkerJobRequestV2 {
    session: InputSessionHandleV2,
    descriptor: SignedParserWorkerJobDescriptorV2,
}

struct RegisterParserWorkerJobResponseV2 {
    extraction: ParserExtractionHandleV2,
}

struct AppendParserWorkerPageFrameRequestV2 {
    extraction: ParserExtractionHandleV2,
    frame: ParserWorkerPageFrameV2,
}

struct AppendParserWorkerPageFrameResponseV2 {
    page_index: u32,
    page_chunk_index: u32,
    ordered_page_frame_transcript_digest: Digest32,
}

struct CommitParserWorkerResultRequestV2 {
    extraction: ParserExtractionHandleV2,
    attestation: SignedParserWorkerResultAttestationV2,
}

struct CommitParserWorkerResultResponseV2 {
    extracted_channel_commitment: InputChannelCommitmentV2,
    parsed_source_provenance_digest: Digest32,
}
```

`PrepareIngressUiAuthentication` is valid only before any byte is accepted.
`AuthenticateIngressUi` accepts only
`UiAuthenticationPurposeV2::IngressInput` at `Ingress8767`, atomically binds
the authenticated principal to the pending task, and returns one
same-boot/same-tab authorization. `BeginInput` consumes that authorization
once. No `AppendInputChunk`, finalize, approval preparation, or content
storage is reachable before this transition.

An exact repeated chunk with the same session/channel/sequence/plaintext
digest/cumulative digest returns the original acknowledgement. Different
bytes or digest at an accepted sequence transitions the input to
`FailedClosed`.

`AppendInputChunk` accepts only `DirectInputChannelV2`; its two variants map
exactly to `InputChannelV2::OriginalSource` and `InputChannelV2::ChatText`.
No decoder, enum conversion, unknown tag, browser field, or generic channel
parameter can select `ExtractedPage`. Only the parser staging operations
48–50 below can commit that channel.

The exact digest chain is:

```text
InputChunkDigest =
  SHA-256("SAVANA_INPUT_CHUNK_V2\0" ||
          session_internal_id ||
          channel_u16be ||
          sequence_u32be ||
          chunk_length_u32be ||
          chunk_bytes)

InputCumulativeDigest[0] =
  SHA-256("SAVANA_INPUT_CHANNEL_BEGIN_V2\0" ||
          session_internal_id ||
          channel_u16be)

InputCumulativeDigest[n + 1] =
  SHA-256("SAVANA_INPUT_CHANNEL_STEP_V2\0" ||
          InputCumulativeDigest[n] ||
          sequence_u32be ||
          InputChunkDigest)
```

kerneld recomputes every digest from decrypted bytes; caller-supplied digests
are comparisons, never authority. `OriginalSource`, `ExtractedPage`, and
`ChatText` sort by their enum tags `1`, `2`, and `3`. `ContentKindV2`
declares one exact allowed channel set: chat requires only `ChatText`; plain
text requires only `OriginalSource`; a parsed document requires
`OriginalSource` and `ExtractedPage`. Missing, duplicate, extra, empty where
forbidden, or mismatched channel commitments fail closed. The declared total
length/digest from `BeginInput`, every page frame, and
`InputSourceProvenanceV2` must equal these kernel-computed commitments before
an approval envelope is signed.

The allowed provenance pairs are exact: `ChatText` requires
`Direct(Chat)`; `PlainText` requires `Direct(Paste)` or
`Direct(FileUpload)`; `ParsedDocument` requires
`ParsedDocument(FileUpload)`. All other content/source/channel combinations
are rejected before approval.

### 5.4 kerneld to execd

| Tag | Operation | Class |
|---:|---|---|
| 0 | `Health` | Query |
| 60 | `Dispatch` | SensitiveOneWayMutation |
| 61 | `QueryByExecutionNonce` | Query |
| 62 | `AcknowledgeCommittedCompletion` | OneWayMutation |
| 63 | `FetchCompletion` | SensitiveQuery |

```rust
struct ExecutorHealthRequestV2;

struct ExecutorHealthResponseV2 {
    ready: bool,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    executor_identity_digest: Digest32,
    seal_key_id: HpkeX25519KeyIdV2,
    journal_schema_version: u16,
    journal_key_epoch: u64,
    connector_set_digest: Digest32,
    bounded_recovery_backlog: u32,
    last_public_error: Option<PublicStableCodeV2>,
}

struct DispatchRequestV2 {
    envelope: SignedSealedExecutionEnvelopeV2,
}

struct DispatchResponseV2 {
    status: ExecutorStatusV2,
}

struct QueryByExecutionNonceRequestV2 {
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
}

enum ExecutorCompletionDescriptorV2 {
    ToolResult {
        result_digest: Digest32,
        encoded_length: u32,
    } = 1,
    FinalReleaseReceipt {
        durable_release_id: DurableReleaseIdV2,
        final_release_receipt_digest: Digest32,
        release_audit_digest: Digest32,
        encoded_length: u32,
    } = 2,
}

enum ExecutorCompletionPayloadV2 {
    ToolResult {
        result: ZeroizingBytesV2,
    } = 1,
    FinalReleaseReceipt {
        receipt: SignedExecutorFinalReleaseReceiptV2,
        provider_evidence: ZeroizingBytesV2,
        audit_evidence: ExecutorFinalReleaseAuditEvidenceV2,
    } = 2,
}

struct AcknowledgeCommittedCompletionRequestV2 {
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    completion: ExecutorCompletionDescriptorV2,
    kernel_commit_digest: Digest32,
}

struct AcknowledgeCommittedCompletionResponseV2 {
    status: ExecutorStatusV2,
}

struct FetchCompletionRequestV2 {
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    completion: ExecutorCompletionDescriptorV2,
}

struct FetchCompletionResponseV2 {
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    effect_started_receipt: SignedExecutorEffectStartedReceiptV2,
    effect_started_receipt_digest: Digest32,
    completion: ExecutorCompletionDescriptorV2,
    payload: ExecutorCompletionPayloadV2,
}

enum ExecutorFailureClassV2 {
    EnvelopeRejectedBeforeEffect = 1,
    FencedBeforeEffect = 2,
    ConnectorUnavailableBeforeEffect = 3,
    ConnectorRejectedBeforeEffect = 4,
    ResourceFailureBeforeEffect = 5,
}

enum ExecutorStatusV2 {
    Unknown {
        proof: CompleteNonceAbsenceProofV2,
    } = 1,
    Prepared = 2,
    EffectStarted {
        effect_started_receipt: SignedExecutorEffectStartedReceiptV2,
        effect_started_receipt_digest: Digest32,
    } = 3,
    CompletionAvailable {
        effect_started_receipt: SignedExecutorEffectStartedReceiptV2,
        effect_started_receipt_digest: Digest32,
        completion: ExecutorCompletionDescriptorV2,
    } = 4,
    FailedNoEffect {
        class: ExecutorFailureClassV2,
    } = 5,
    Indeterminate {
        effect_started_receipt:
            Option<SignedExecutorEffectStartedReceiptV2>,
        effect_started_receipt_digest: Option<Digest32>,
    } = 6,
    Acknowledged = 7,
}
```

`ExecutorHealthResponseV2.connector_set_digest` is not a locally summarized
health value. It equals byte-for-byte the complete connector-set digest in the
active signed `ExecutorConnectorRegistry` manifest component, whose canonical
items, count, domain, sort key, and duplicate rejection are fixed by that
component. Execd recomputes the component digest at start; a different,
partial, availability-filtered, or runtime-discovered set fences the service.

The same nonce, dispatch-core digest, and dispatch-subject digest returns prior
state. The same nonce with a different core or subject digest poisons that
nonce and no connector is invoked.

The two `Indeterminate` receipt options are always both `Some` or both
`None`. They are both `Some` whenever the exact execd record chain contains
an `EffectStarted`, `ProviderRetryPrepared`, `ProviderResponseRetained`, or
`ReleaseEvidencePrepared` ancestor, and the digest must equal
`SignedExecutorEffectStartedReceiptDigest` of those exact signed bytes under
the head-projection rules in section 13.2. Execd resolves the full object from
the sealed receipt record before encoding the response. They may both be
`None` only when the authenticated journal/index state contains no such
ancestor and no other known-effect lineage. A missing, undecryptable, or
digest-mismatched sealed receipt for a chain that requires one fails stop; it
cannot be downgraded to a receipt-free `Indeterminate`.

`QueryByExecutionNonce` is status-only and never contains result/release
evidence bytes, journal ciphertext, a connector receipt, or provider text.
`FetchCompletion` is the sole
completion-reading operation. Execd authenticates the exact kerneld peer,
decrypts its at-rest completion into zeroizing storage, and returns either the
raw bounded tool result or the typed signed final-release receipt/provider
evidence only inside the sensitive transport record. Kerneld verifies the
nonce/core/subject and descriptor/payload digests before the branch-specific
commit gate. No completion-unsealing key is exported from execd.

`Unknown` is valid only when execd has verified its complete nonce index and
hash chain from the retained genesis/checkpoint through the current journal
head and returns an authenticated `CompleteNonceAbsenceProofV2` binding the
nonce, current journal head, index generation, deployment generation, and
effect-fence epoch. A missing/corrupt/incompletely rebuilt index returns
`Indeterminate`, never `Unknown`, only when execd can still select the exact
nonce chain and satisfy the receipt option matrix above. Otherwise the query
fails stop and cannot manufacture a receipt-free status.

### 5.5 agentd/ingressd to approvald

The operation tables are role-specific even where numeric tags match:

| Agent tag | Operation | Class |
|---:|---|---|
| 0 | `Health` | Query |
| 20 | `RegisterSignedApprovalEnvelope` | SensitiveIdempotentMutation |
| 21 | `GetApprovalSettlement` | SensitiveQuery |
| 22 | `RegisterUiAuthentication` | SensitiveIdempotentMutation |
| 23 | `ConsumeUiAuthenticationSettlement` | SensitiveOneWayMutation |
| 24 | `TerminalizeAgentUiAuthenticationAttempt` | SensitiveIdempotentMutation |

| Ingress tag | Operation | Class |
|---:|---|---|
| 0 | `Health` | Query |
| 20 | `RegisterSignedApprovalEnvelope` | SensitiveIdempotentMutation |
| 21 | `GetApprovalSettlement` | SensitiveQuery |
| 22 | `RegisterUiAuthentication` | SensitiveIdempotentMutation |
| 23 | `ConsumeUiAuthenticationSettlement` | SensitiveOneWayMutation |

| Admin tag | Operation | Class |
|---:|---|---|
| 0 | `Health` | Query |
| 100 | `CreateEnrollmentCode` | SensitiveOneWayMutation |
| 101 | `RevokeCredential` | OneWayMutation |

```rust
struct ApprovalHealthRequestV2;

struct ApprovalHealthResponseV2 {
    ready: bool,
    state: PublicServiceStateV2,
}

struct RegisterIngressSignedApprovalEnvelopeRequestV2 {
    envelope: SignedApprovalEnvelopeV2,
    display_authentication: SignedUiAuthenticationEnvelopeV2,
}

struct RegisterIngressSignedApprovalEnvelopeResponseV2 {
    approval: IngressApprovalRecordHandleV2,
    ui: UiActionV2,
}

struct GetIngressApprovalSettlementRequestV2 {
    approval: IngressApprovalRecordHandleV2,
}

struct GetIngressApprovalSettlementResponseV2 {
    view: ApprovalSettlementViewV2,
}

struct RegisterAgentSignedApprovalEnvelopeRequestV2 {
    envelope: SignedApprovalEnvelopeV2,
    display_authentication: SignedUiAuthenticationEnvelopeV2,
}

enum AgentApprovalRecordTargetV2 {
    Tool(ToolApprovalRecordHandleV2) = 1,
    Release(ReleaseApprovalRecordHandleV2) = 2,
}

struct RegisterAgentSignedApprovalEnvelopeResponseV2 {
    approval: AgentApprovalRecordTargetV2,
    ui: UiActionV2,
}

struct GetAgentApprovalSettlementRequestV2 {
    approval: AgentApprovalRecordTargetV2,
}

struct GetAgentApprovalSettlementResponseV2 {
    view: ApprovalSettlementViewV2,
}

enum ApprovalSettlementViewV2 {
    Pending,
    Denied { settlement: SignedApprovalSettlementV2 },
    Expired,
    Approved { settlement: SignedApprovalSettlementV2 },
}

struct RegisterAgentUiAuthenticationRequestV2 {
    envelope: SignedUiAuthenticationEnvelopeV2,
}

struct RegisterAgentUiAuthenticationResponseV2 {
    authentication: AgentUiAuthenticationRecordHandleV2,
    ui: UiActionV2,
}

struct ConsumeAgentUiAuthenticationSettlementRequestV2 {
    authentication: AgentUiAuthenticationRecordHandleV2,
    transfer: AgentUiAuthenticationSettlementTransferCapabilityV2,
}

struct ConsumeAgentUiAuthenticationSettlementResponseV2 {
    settlement: SignedUiAuthenticationSettlementV2,
}

struct TerminalizeAgentUiAuthenticationAttemptRequestV2 {
    closure: SignedAgentAuthenticationClosureDescriptorV2,
    client_request_nonce: Nonce32,
}

struct TerminalizeAgentUiAuthenticationAttemptResponseV2 {
    proof: SignedAgentAuthenticationAttemptClosureProofV2,
}

struct RegisterIngressUiAuthenticationRequestV2 {
    envelope: SignedUiAuthenticationEnvelopeV2,
}

struct RegisterIngressUiAuthenticationResponseV2 {
    authentication: IngressUiAuthenticationRecordHandleV2,
    ui: UiActionV2,
}

struct ConsumeIngressUiAuthenticationSettlementRequestV2 {
    authentication: IngressUiAuthenticationRecordHandleV2,
    transfer: IngressUiAuthenticationSettlementTransferCapabilityV2,
}

struct ConsumeIngressUiAuthenticationSettlementResponseV2 {
    settlement: SignedUiAuthenticationSettlementV2,
}

struct CreateEnrollmentCodeRequestV2 {
    enrollment_profile: EnrollmentProfileIdV2,
    client_request_nonce: Nonce32,
}

struct CreateEnrollmentCodeResponseV2 {
    enrollment: EnrollmentHandleV2,
    code: ZeroizingTextV2,
    expires_at: UnixMillis,
}

struct RevokeCredentialRequestV2 {
    credential_digest: Digest32,
    reason: ClosedCredentialRevocationReasonV2,
}

struct RevokeCredentialResponseV2 {
    state: CredentialPublicStateV2,
}
```

For approval envelopes, the ingress endpoint accepts only purpose `Ingress`;
the agent endpoint accepts only `ToolExecution` or `FinalRelease`.
`RegisterSignedApprovalEnvelope` atomically registers the matching
`ApprovalDisplay` UI-authentication envelope but exposes no display.

For UI authentication, IngressApproval tags 22–23 accept only
`IngressInput` records whose fixed post-authentication destination is
`Ingress8767`; AgentApproval tags 22–23 accept only `AgentContent` records
whose destination is `Agent8768`. Approvald's local port-8766 state machine
accepts only `ApprovalDisplay` records for local consumption. All three
WebAuthn ceremonies run directly against approvald at `Approval8766`. A role,
purpose, authentication origin, return origin, task, envelope, or principal
mismatch closes without a settlement. No decoder accepts a UI-authentication
artifact as an approval-decision artifact or vice versa.

The daemon UDS roles never begin or finish WebAuthn and never receive or
return public-key options, challenges, assertions, credential data, or
decision data. Tag 22 registers the exact signed envelope and returns only an
approvald-owned record handle plus a one-use transfer to the 8766 browser
state machine. After approvald atomically verifies the assertion, advances
the credential counter, signs, and stores the exact settlement, its 8766
response emits a distinct random
`IngressUiAuthenticationSettlementTransferCapabilityV2` or
`AgentUiAuthenticationSettlementTransferCapabilityV2` in a fixed form POST
to the bound ingress or agent origin. Tag 23 atomically consumes that transfer
together with the exact record handle and returns the already stored signed
settlement. The transfer cannot select a record, purpose, principal, or
settlement and exact replay returns the same stored response only under the
same replay key; reuse from another browser tab, role, origin, or record is
rejected.

AgentApproval tag 24 accepts only an `AgentContent` envelope already bound to
the exact durable recovery attempt. Under approvald's durable record,
ceremony, transfer, settlement, and replay locks it atomically makes every
unconsumed purpose-specific record and transfer unusable, consumes or
tombstones them, and emits a signed closure proof. It never returns an
assertion, settlement, transfer capability, or content. A proof saying the
attempt was redeemed is evidence for fail-stop invalidation, not permission
to mint a replacement.

Registration accepts only the exact daemon-supplied signed envelope pair.
Both envelopes must contain the same durable task, manifest, generation,
principal and display/approval binding. There is no public task handle or
independent purpose, principal, display, challenge, decision, credential,
destination, or approval field.

The success-variant mapping is closed:
`RegisterIngressUiAuthentication` returns only `UiActionV2::OpenIngress`,
`RegisterAgentUiAuthentication` returns only `OpenAgent`, and either
role's `Register*SignedApprovalEnvelope` returns only `OpenApproval`.
All carry `authentication_origin=Approval8766`; return origins are exactly
8767, 8768, and 8766 respectively. `None`, a cross-variant transfer type, or
any other origin pair is rejected as a noncanonical success record.

The root-admin endpoint uses `EndpointRoleV2::ApprovalAdmin` and the common V2
encrypted handshake. Its OS peer and transport-key identities are fixed by the
deployment companion. It exposes no signing, settlement, browser-session,
ingress, tool, release, or kernel operation.

### 5.6 Complete operation contract

The following table is exhaustive. `Q` means no replay record; `BR` means the
request replay key in section 10 and current-boot handles; `DR` means an
additional durable semantic index survives restart; `OW` means atomic
authorization consumption; `AR` means approval-envelope/settlement digest
index; `NR` means executor nonce index; `AD` means admin durable replay.
`TaskQ` is the sole boot-independent public query and exists only on
JarvisAgentControl. `CorrelationQ` is the agentd-only, non-bearer,
service-to-service durable status query. Every capability target is
current-boot.

| Role/tag | Request → success response | Error set | Replay | Restart |
|---|---|---|---|---|
| JarvisAgentControl/0 | `AgentControlHealthRequestV2` → `AgentControlHealthResponseV2` | `E_HEALTH` | Q | current boot |
| JarvisAgentControl/10 | `PrepareIngressRequestV2` → `PrepareIngressResponseV2` | `E_CONTROL_MUTATION` | DR | result recoverable by task |
| JarvisAgentControl/11 | `GetTaskStatusRequestV2` → `GetTaskStatusResponseV2` | `E_QUERY` | Q | TaskQ |
| JarvisAgentControl/12 | `CancelTaskRequestV2` → `CancelTaskResponseV2` | `E_CONTROL_MUTATION` | OW | same boot only |
| AgentKernel/0 | `KernelAgentHealthRequestV2` → `KernelAgentHealthResponseV2` | `E_HEALTH` | Q | current boot |
| AgentKernel/20 | `ClaimAgentSessionRequestV2` → `ClaimAgentSessionResponseV2` | `E_APPROVAL` | BR+OW | same boot only |
| AgentKernel/21 | `PrepareFollowupIngressRequestV2` → `PrepareFollowupIngressResponseV2` | `E_INPUT` | BR | same boot only |
| AgentKernel/22 | `GetAgentSessionStatusRequestV2` → `GetAgentSessionStatusResponseV2` | `E_QUERY` | Q | same boot only |
| AgentKernel/23 | `PreparePlannerCallRequestV2` → `PreparePlannerCallResponseV2` | `E_POLICY` | BR | same boot only |
| AgentKernel/24 | `CommitPlannerValueRequestV2` → `CommitPlannerValueResponseV2` | `E_POLICY` | BR | same boot only |
| AgentKernel/25 | `DeriveValueRequestV2` → `DeriveValueResponseV2` | `E_POLICY` | BR | same boot only |
| AgentKernel/26 | `ProposeToolCallRequestV2` → `ProposeToolCallResponseV2` | `E_POLICY` | DR | intent durable |
| AgentKernel/27 | `EvaluateToolCallRequestV2` → `EvaluateToolCallResponseV2` | `E_POLICY` | BR | intent durable/status-only |
| AgentKernel/28 | `AuthorizeToolCallRequestV2` → `AuthorizeToolCallResponseV2` | `E_APPROVAL` | AR+OW | intent durable/status-only |
| AgentKernel/29 | `DispatchExecutionRequestV2` → `DispatchExecutionResponseV2` | `E_EXECUTION` | OW+NR | durable by task/intent |
| AgentKernel/30 | `GetExecutionStatusRequestV2` → `GetExecutionStatusResponseV2` | `E_QUERY` | Q | same boot only |
| AgentKernel/31 | `ReadAgentViewRequestV2` → `ReadAgentViewResponseV2` | `E_CONTROL_MUTATION` | BR | same boot only |
| AgentKernel/32 | `PrepareReleaseRequestV2` → `PrepareReleaseResponseV2` | `E_POLICY` | BR | same boot only |
| AgentKernel/33 | `AuthorizeReleaseRequestV2` → `AuthorizeReleaseResponseV2` | `E_APPROVAL` | AR+OW | release durable/status-only |
| AgentKernel/34 | `DispatchReleaseRequestV2` → `DispatchReleaseResponseV2` | `E_EXECUTION` | OW+NR | durable by task |
| AgentKernel/35 | `GetReleaseStatusRequestV2` → `GetReleaseStatusResponseV2` | `E_QUERY` | Q | same boot only |
| AgentKernel/36 | `RevokeVaultRequestV2` → `RevokeVaultResponseV2` | `E_CONTROL_MUTATION` | OW | same boot; durable outcome |
| AgentKernel/37 | `CloseAgentSessionRequestV2` → `CloseAgentSessionResponseV2` | `E_CONTROL_MUTATION` | OW | same boot; durable outcome |
| AgentKernel/38 | `PrepareNewIngressRequestV2` → `PrepareNewIngressResponseV2` | `E_INPUT` | DR | correlation survives; handles expire |
| AgentKernel/39 | `PrepareAgentUiAuthenticationRequestV2` → `PrepareAgentUiAuthenticationResponseV2` | `E_APPROVAL` | BR | same boot only |
| AgentKernel/40 | `AuthenticateAgentUiRequestV2` → `AuthenticateAgentUiResponseV2` | `E_APPROVAL` | OW | same boot only |
| AgentKernel/41 | `GetKernelTaskStatusRequestV2` → `GetKernelTaskStatusResponseV2` | `E_QUERY` | Q | CorrelationQ |
| AgentKernel/42 | `CancelKernelTaskRequestV2` → `CancelKernelTaskResponseV2` | `E_CONTROL_MUTATION` | BR+OW | creation boots only |
| AgentKernel/43 | `ResumeCommittedAgentAuthenticationRequestV2` → `ResumeCommittedAgentAuthenticationResponseV2` | `E_APPROVAL` | BR | durable `CommittedUnclaimed`; fresh handles |
| IngressKernel/0 | `KernelIngressHealthRequestV2` → `KernelIngressHealthResponseV2` | `E_HEALTH` | Q | current boot |
| IngressKernel/40 | `BeginInputRequestV2` → `BeginInputResponseV2` | `E_INPUT` | BR | precommit restart invalidates |
| IngressKernel/41 | `AppendInputChunkRequestV2` → `AppendInputChunkResponseV2` | `E_INPUT` | BR | precommit restart invalidates |
| IngressKernel/42 | `FinalizeInputRequestV2` → `FinalizeInputResponseV2` | `E_INPUT` | BR | precommit restart invalidates |
| IngressKernel/43 | `CommitInputSettlementRequestV2` → `CommitInputSettlementResponseV2` | `E_APPROVAL` | OW+DR | durable outcome via correlation |
| IngressKernel/44 | `AbortInputRequestV2` → `AbortInputResponseV2` | `E_INPUT` | OW | terminal survives |
| IngressKernel/45 | `GetInputStatusRequestV2` → `GetInputStatusResponseV2` | `E_QUERY` | Q | same boot only |
| IngressKernel/46 | `PrepareIngressUiAuthenticationRequestV2` → `PrepareIngressUiAuthenticationResponseV2` | `E_APPROVAL` | BR+OW | same boot only |
| IngressKernel/47 | `AuthenticateIngressUiRequestV2` → `AuthenticateIngressUiResponseV2` | `E_APPROVAL` | BR+OW | same boot only |
| IngressKernel/48 | `RegisterParserWorkerJobRequestV2` → `RegisterParserWorkerJobResponseV2` | `E_INPUT` | BR | parser staging, same boot |
| IngressKernel/49 | `AppendParserWorkerPageFrameRequestV2` → `AppendParserWorkerPageFrameResponseV2` | `E_INPUT` | BR | parser staging, same boot |
| IngressKernel/50 | `CommitParserWorkerResultRequestV2` → `CommitParserWorkerResultResponseV2` | `E_INPUT` | OW | durable input status |
| KernelExecutor/0 | `ExecutorHealthRequestV2` → `ExecutorHealthResponseV2` | `E_HEALTH` | Q | persistent executor |
| KernelExecutor/60 | `DispatchRequestV2` → `DispatchResponseV2` | `E_EXECUTION` | NR+OW | durable nonce |
| KernelExecutor/61 | `QueryByExecutionNonceRequestV2` → `ExecutorStatusV2` | `E_QUERY` | Q | durable nonce |
| KernelExecutor/62 | `AcknowledgeCommittedCompletionRequestV2` → `AcknowledgeCommittedCompletionResponseV2` | `E_EXECUTION` | NR+OW | durable tombstone |
| KernelExecutor/63 | `FetchCompletionRequestV2` → `FetchCompletionResponseV2` | `E_EXECUTION` | Q | durable until ack/expiry |
| AgentApproval/0 | `ApprovalHealthRequestV2` → `ApprovalHealthResponseV2` | `E_HEALTH` | Q | persistent approvald |
| AgentApproval/20 | `RegisterAgentSignedApprovalEnvelopeRequestV2` → `RegisterAgentSignedApprovalEnvelopeResponseV2` | `E_APPROVAL` | AR | persistent envelope |
| AgentApproval/21 | `GetAgentApprovalSettlementRequestV2` → `GetAgentApprovalSettlementResponseV2` | `E_QUERY` | Q | persistent envelope |
| AgentApproval/22 | `RegisterAgentUiAuthenticationRequestV2` → `RegisterAgentUiAuthenticationResponseV2` | `E_APPROVAL` | AR | envelope survives until expiry |
| AgentApproval/23 | `ConsumeAgentUiAuthenticationSettlementRequestV2` → `ConsumeAgentUiAuthenticationSettlementResponseV2` | `E_APPROVAL` | AR+OW | exact stored settlement |
| AgentApproval/24 | `TerminalizeAgentUiAuthenticationAttemptRequestV2` → `TerminalizeAgentUiAuthenticationAttemptResponseV2` | `E_APPROVAL` | AR+OW | signed closure proof durable |
| IngressApproval/0 | `ApprovalHealthRequestV2` → `ApprovalHealthResponseV2` | `E_HEALTH` | Q | persistent approvald |
| IngressApproval/20 | `RegisterIngressSignedApprovalEnvelopeRequestV2` → `RegisterIngressSignedApprovalEnvelopeResponseV2` | `E_APPROVAL` | AR | persistent envelope |
| IngressApproval/21 | `GetIngressApprovalSettlementRequestV2` → `GetIngressApprovalSettlementResponseV2` | `E_QUERY` | Q | persistent envelope |
| IngressApproval/22 | `RegisterIngressUiAuthenticationRequestV2` → `RegisterIngressUiAuthenticationResponseV2` | `E_APPROVAL` | AR | envelope survives until expiry |
| IngressApproval/23 | `ConsumeIngressUiAuthenticationSettlementRequestV2` → `ConsumeIngressUiAuthenticationSettlementResponseV2` | `E_APPROVAL` | AR+OW | exact stored settlement |
| ApprovalAdmin/0 | `ApprovalHealthRequestV2` → `ApprovalHealthResponseV2` | `E_HEALTH` | Q | persistent approvald |
| ApprovalAdmin/100 | `CreateEnrollmentCodeRequestV2` → `CreateEnrollmentCodeResponseV2` | `E_ADMIN` | AD+OW | persistent enrollment |
| ApprovalAdmin/101 | `RevokeCredentialRequestV2` → `RevokeCredentialResponseV2` | `E_ADMIN` | AD+OW | persistent revocation |

`KernelIngressHealth*` has the same two fields and encoding as
`KernelAgentHealth*` but is a distinct Rust type. Every row's request and
response is one canonical array and one encrypted application record.

### 5.7 Browser origins and external planner

The complete production loopback HTTP surface is:

| Origin | Allowed routes |
|---|---|
| `http://localhost:8765` | `GET /v2/shell`, `GET /v2/bootstrap/<kind>/<selector>`, `POST /v2/bootstrap/continue` |
| `http://localhost:8766` | `GET /v2/enrollment/bootstrap`, `POST /v2/ui-auth/accept`, `POST /v2/ui-auth/begin`, `POST /v2/ui-auth/finish`, `POST /v2/approval/display`, `POST /v2/approval/decision/begin`, `POST /v2/approval/decision/finish`, `POST /v2/webauthn/enroll/begin`, `POST /v2/webauthn/enroll/finish` |
| `http://localhost:8767` | `POST /v2/bootstrap/accept`, `POST /v2/ui-auth/complete`, `POST /v2/input/begin`, `POST /v2/input/chunk`, `POST /v2/input/finalize`, `POST /v2/input/abort` |
| `http://localhost:8768` | `POST /v2/ui-auth/complete`, `POST /v2/agent/view`, `POST /v2/agent/action` |

Every other path or method returns a fixed 404 with no reflection. All four
origins reject any request containing `Cookie`, `Authorization`,
`Proxy-Authorization`, or a nonempty `Sec-WebSocket-Protocol`; never emit
`Set-Cookie`; expose no WebSocket, EventSource, service worker, upload
redirect, or CORS permission; require the exact `Host` and allowed `Origin`;
set `Cache-Control: no-store`, `Pragma: no-cache`,
`Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and CSP
`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self';
connect-src 'self'; form-action 'self' http://localhost:8766
http://localhost:8767 http://localhost:8768; frame-ancestors 'none';
base-uri 'none'`.

Agentd is the sole listener, selector resolver, and signed-static-artifact
owner for port 8765. `Health`, `PrepareIngress`, `GetTaskStatus`, and
`CancelTask` exist only on the mutually authenticated
`JarvisAgentControl` UDS/XPC surface in section 5.1. They have no HTTP
decoder, route alias, form carrier, JavaScript bridge, or loopback fallback.
In particular no task-status or task-cancellation HTTP path exists, and a
`TaskHandleV2` presented to any HTTP decoder is rejected before lookup.

Only the two fixed static GET classes above are legal without `Origin`.
Every POST requires an exact allowed origin. Ingress
`/v2/bootstrap/accept` accepts only carrier tag 1 from 8765 or the distinct
follow-up carrier tag 7 from 8768; the two source-origin bindings cannot be
substituted even though both carry the same kernel transfer newtype.
Approval and agent selectors go directly from 8765 to approvald
`/v2/ui-auth/accept` with their already registered, distinctly typed
transfers. Approvald also accepts the ingress UI-auth transfer subsequently
posted by 8767. Only 8766 exposes UI-auth begin/finish. A content-origin
`/v2/ui-auth/complete` accepts only approvald's fixed form POST carrying the
matching one-use settlement transfer. All content POSTs require their own
exact origin. No CORS response is emitted.

Port 8765 accepts only the signed static shell and the two fixed bootstrap
GET/continue classes. It accepts no user-content body, filename, generic text
field, file, planner/tool field, task-status/cancel body, or content-returning
route. Its selector GET renders only fixed HTML. Continue consumes the
selector and returns an exact fixed, kind-specific form. `Ingress` carries
`KernelIngressBootstrapTransferCapabilityV2` to 8767; `Approval` carries
`ApprovalDisplayAuthenticationTransferCapabilityV2` to 8766; `Agent` carries
`AgentUiAuthenticationTransferCapabilityV2` to 8766. Cross-kind decoding is
impossible and neither selector nor transfer contains a public task handle or
content authority.

The 8767 bootstrap acceptor renders only a fixed wait shell, obtains the exact
kerneld-signed ingress UI-authentication envelope, registers it over
IngressApproval UDS, and returns a fixed form carrying the exact
`IngressUiAuthenticationTransferCapabilityV2` to 8766. Approvald accept
creates exactly one of `IngressUiPreAuthenticationTabCapabilityV2`,
`ApprovalDisplayUiPreAuthenticationTabCapabilityV2`, or
`AgentUiPreAuthenticationTabCapabilityV2`; approvald alone
serves the options, consumes the assertion, verifies WebAuthn, advances the
counter, signs, and stores the settlement. For ingress or agent purpose, its
success response is a fixed form POST carrying only a fresh
`IngressUiAuthenticationSettlementTransferCapabilityV2` or
`AgentUiAuthenticationSettlementTransferCapabilityV2` back to the bound
content origin. That daemon consumes the transfer over its
role-specific approvald UDS, passes the exact stored settlement to kerneld,
and returns its tab capability only after kerneld authorization. No proxy or
service-to-service API exposes WebAuthn options, assertions, challenges, or
completion authority.

Approvald returns `ApprovalTabSessionCapabilityV2` only after a distinct
`ApprovalDisplay` UI authentication at 8766. Before that transition it may
render a fixed deny/error shell but cannot load, render, measure, cache, or
return any bytes selected by `display_digest`. Display retrieval requires the
tab capability. This rule applies identically to ingress, tool-execution, and
final-release approval displays. Approve/deny then requires a second WebAuthn ceremony with a
separate, previously unused `decision_challenge` and
`ApprovalDecisionCeremonyCapabilityV2`.

The sole external planner exchange is TLS 1.3 `POST /savana.planner.v2/plan`
to the exact manifest-pinned origin. It uses the agentd-only mTLS credential,
the pinned server SPKI, `Content-Type: application/cbor`, one canonical
`PlannerEnvelopeV2` body, and one canonical `PlannerPlanV2` response. Redirect,
proxy discovery, compression, cookies, generic authorization headers,
trailers, telemetry bodies, retries, and provider error bodies are forbidden.
The planner client API accepts only `PlannerEnvelopeV2`; there is no overload
accepting `AgentViewV2`, text, bytes, maps, or arbitrary JSON. Responses are
untrusted and pass the kernel validation described below.

Loopback bodies are closed as follows:

| Route class | Request body | Success body |
|---|---|---|
| 8765 bootstrap `GET` | empty | exact signed static HTML/JS artifact; no task/content data |
| 8765 bootstrap continue | canonical CBOR `ContinueJarvisBootstrapRequestV2` | exact fixed cross-origin form POST containing one `JarvisBootstrapContinueTransferV2` variant |
| ingress bootstrap accept | form-urlencoded exact `KernelIngressBootstrapTransferCapabilityV2` | fixed no-content wait HTML followed by a fixed form to 8766 |
| UI-auth accept at 8766 | form-urlencoded exact `transfer=<base64url32>` | fixed authentication HTML carrying one tab-memory pre-auth capability |
| UI-auth begin | canonical CBOR `UiAuthenticationBrowserBeginRequestV2` | canonical CBOR `UiAuthenticationBrowserBeginResponseV2` |
| UI-auth finish | canonical CBOR `UiAuthenticationBrowserFinishRequestV2` | canonical CBOR `UiAuthenticationBrowserFinishResponseV2` |
| UI-auth complete at 8767/8768 | form-urlencoded exact `transfer=<base64url32>` | fixed no-store HTML workspace; the purpose-specific tab capability exists only in the response body and subsequent same-origin canonical-CBOR requests |
| approval display | canonical CBOR `ApprovalDisplayBrowserRequestV2` | canonical CBOR `ApprovalDisplayViewV2` |
| approval decision begin | canonical CBOR `ApprovalDecisionBrowserBeginRequestV2` | canonical CBOR `ApprovalDecisionBrowserBeginResponseV2` |
| approval decision finish | canonical CBOR `ApprovalDecisionBrowserFinishRequestV2` | canonical CBOR `ApprovalDecisionBrowserFinishResponseV2` |
| enrollment begin | canonical CBOR `BeginEnrollmentBrowserRequestV2` | canonical CBOR `BeginEnrollmentBrowserResponseV2` |
| enrollment finish | canonical CBOR `FinishEnrollmentBrowserRequestV2` | canonical CBOR `FinishEnrollmentBrowserResponseV2` |
| ingress begin/chunk/finalize/abort | canonical CBOR `IngressBrowserRequestV2` | canonical CBOR `IngressBrowserMutationResponseV2` |
| agent view/action | canonical CBOR `AgentBrowserRequestV2` | canonical CBOR `AgentBrowserReadViewResponseV2` or `AgentBrowserMutationResponseV2` |

```rust
struct ContinueJarvisBootstrapRequestV2 {
    selector: JarvisBootstrapSelectorV2,
    client_request_nonce: Nonce32,
}

enum JarvisBootstrapContinueTransferV2 {
    Ingress(KernelIngressBootstrapTransferCapabilityV2) = 1,
    Approval(ApprovalDisplayAuthenticationTransferCapabilityV2) = 2,
    Agent(AgentUiAuthenticationTransferCapabilityV2) = 3,
}

enum UiAuthenticationBrowserBeginRequestV2 {
    Ingress {
        pre_authentication: IngressUiPreAuthenticationTabCapabilityV2,
        client_request_nonce: Nonce32,
    } = 1,
    ApprovalDisplay {
        pre_authentication: ApprovalDisplayUiPreAuthenticationTabCapabilityV2,
        client_request_nonce: Nonce32,
    } = 2,
    Agent {
        pre_authentication: AgentUiPreAuthenticationTabCapabilityV2,
        client_request_nonce: Nonce32,
    } = 3,
}

enum UiAuthenticationBrowserBeginResponseV2 {
    Ingress {
        ceremony: IngressUiAuthenticationBrowserCeremonyCapabilityV2,
        public_key_options_json: ZeroizingBytesV2,
    } = 1,
    ApprovalDisplay {
        ceremony: ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
        public_key_options_json: ZeroizingBytesV2,
    } = 2,
    Agent {
        ceremony: AgentUiAuthenticationBrowserCeremonyCapabilityV2,
        public_key_options_json: ZeroizingBytesV2,
    } = 3,
}

struct WebAuthnAssertionV2 {
    credential_id: ZeroizingBytesV2,
    authenticator_data: ZeroizingBytesV2,
    client_data_json: ZeroizingBytesV2,
    signature: ZeroizingBytesV2,
    user_handle: ZeroizingBytesV2,
}

enum UiAuthenticationBrowserFinishRequestV2 {
    Ingress {
        ceremony: IngressUiAuthenticationBrowserCeremonyCapabilityV2,
        client_request_nonce: Nonce32,
        assertion: WebAuthnAssertionV2,
    } = 1,
    ApprovalDisplay {
        ceremony: ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
        client_request_nonce: Nonce32,
        assertion: WebAuthnAssertionV2,
    } = 2,
    Agent {
        ceremony: AgentUiAuthenticationBrowserCeremonyCapabilityV2,
        client_request_nonce: Nonce32,
        assertion: WebAuthnAssertionV2,
    } = 3,
}

enum UiAuthenticationBrowserFinishResponseV2 {
    TransferToIngress {
        return_origin: FixedOriginV2,
        transfer: IngressUiAuthenticationSettlementTransferCapabilityV2,
    } = 1,
    ApprovalDisplayReady {
        tab: ApprovalTabSessionCapabilityV2,
    } = 2,
    TransferToAgent {
        return_origin: FixedOriginV2,
        transfer: AgentUiAuthenticationSettlementTransferCapabilityV2,
    } = 3,
}

struct IngressUiAuthenticationCompleteBrowserRequestV2 {
    transfer: IngressUiAuthenticationSettlementTransferCapabilityV2,
}

struct IngressUiAuthenticationCompleteBrowserResponseV2 {
    tab: IngressTabSessionCapabilityV2,
}

struct AgentUiAuthenticationCompleteBrowserRequestV2 {
    transfer: AgentUiAuthenticationSettlementTransferCapabilityV2,
}

struct AgentUiAuthenticationCompleteBrowserResponseV2 {
    tab: AgentTabSessionCapabilityV2,
    initial_document: AgentMaskedDocumentRefV2,
}

struct ApprovalDisplayBrowserRequestV2 {
    tab: ApprovalTabSessionCapabilityV2,
}

struct ApprovalDisplayViewV2 {
    purpose: ApprovalPurposeV2,
    template: StaticTemplateIdV2,
    fields: BoundedVec<AgentViewFieldV2, 256>,
}

struct ApprovalDecisionBrowserBeginRequestV2 {
    tab: ApprovalTabSessionCapabilityV2,
    client_request_nonce: Nonce32,
    decision: ApprovalDecisionV2,
}

struct ApprovalDecisionBrowserBeginResponseV2 {
    ceremony: ApprovalDecisionCeremonyCapabilityV2,
    public_key_options_json: ZeroizingBytesV2,
}

struct ApprovalDecisionBrowserFinishRequestV2 {
    ceremony: ApprovalDecisionCeremonyCapabilityV2,
    client_request_nonce: Nonce32,
    assertion: WebAuthnAssertionV2,
}

enum ApprovalDecisionBrowserFinishResponseV2 {
    Denied = 1,
    Approved = 2,
}

struct BeginEnrollmentBrowserRequestV2 {
    enrollment: EnrollmentHandleV2,
    client_request_nonce: Nonce32,
    code: ZeroizingTextV2,
}

struct BeginEnrollmentBrowserResponseV2 {
    ceremony: EnrollmentCeremonyCapabilityV2,
    creation_options_json: ZeroizingBytesV2,
}

struct FinishEnrollmentBrowserRequestV2 {
    ceremony: EnrollmentCeremonyCapabilityV2,
    client_request_nonce: Nonce32,
    credential_id: ZeroizingBytesV2,
    client_data_json: ZeroizingBytesV2,
    attestation_object: ZeroizingBytesV2,
}

struct FinishEnrollmentBrowserResponseV2 {
    credential_digest: Digest32,
    state: CredentialPublicStateV2,
}

enum IngressBrowserRequestV2 {
    Begin {
        tab: IngressTabSessionCapabilityV2,
        client_request_nonce: Nonce32,
        content_kind: ContentKindV2,
        declared_total_bytes: u64,
        declared_content_digest: Option<Digest32>,
    } = 1,
    Append {
        tab: IngressTabSessionCapabilityV2,
        client_request_nonce: Nonce32,
        sequence: u32,
        chunk: ZeroizingBytesV2,
    } = 2,
    Finalize {
        tab: IngressTabSessionCapabilityV2,
        client_request_nonce: Nonce32,
        declared_content_digest: Digest32,
    } = 3,
    Abort {
        tab: IngressTabSessionCapabilityV2,
        client_request_nonce: Nonce32,
    } = 4,
}

enum FixedBrowserFormPostCarrierV2 {
    JarvisToIngressBootstrap {
        transfer: KernelIngressBootstrapTransferCapabilityV2,
    } = 1,
    JarvisToApprovalDisplayAuthentication {
        transfer: ApprovalDisplayAuthenticationTransferCapabilityV2,
    } = 2,
    JarvisToAgentAuthentication {
        transfer: AgentUiAuthenticationTransferCapabilityV2,
    } = 3,
    IngressToApprovalAuthentication {
        transfer: IngressUiAuthenticationTransferCapabilityV2,
    } = 4,
    ApprovalToIngressCompletion {
        transfer: IngressUiAuthenticationSettlementTransferCapabilityV2,
    } = 5,
    ApprovalToAgentCompletion {
        transfer: AgentUiAuthenticationSettlementTransferCapabilityV2,
    } = 6,
    AgentToIngressFollowupBootstrap {
        transfer: KernelIngressBootstrapTransferCapabilityV2,
    } = 7,
    AgentToApprovalDisplayAuthentication {
        transfer: ApprovalDisplayAuthenticationTransferCapabilityV2,
    } = 8,
    IngressToApprovalDisplayAuthentication {
        transfer: ApprovalDisplayAuthenticationTransferCapabilityV2,
    } = 9,
}

enum IngressBrowserMutationResponseV2 {
    Begun {
        next_sequence: u32,
    } = 1,
    ChunkAccepted {
        acknowledged_sequence: u32,
        cumulative_digest: Digest32,
    } = 2,
    FinalizeOpenApproval {
        post: FixedBrowserFormPostCarrierV2,
    } = 3,
    Aborted = 4,
}

enum AgentBrowserActionV2 {
    PrepareFollowupIngress = 1,
    RunPlanner = 2,
    ProposePlanStep(AgentPlanStepRefV2) = 3,
    EvaluatePending(AgentPendingToolCallRefV2) = 4,
    DispatchTicket(AgentExecutionTicketRefV2) = 5,
    PrepareRelease(AgentMaskedDocumentRefV2) = 6,
    DispatchRelease(AgentReleaseTicketRefV2) = 7,
    RevokeVault(AgentMaskedDocumentRefV2) = 8,
    CloseSession = 9,
    RefreshExecution(AgentExecutionRefV2) = 10,
    RefreshRelease(AgentReleaseRefV2) = 11,
}

enum AgentBrowserRequestV2 {
    ReadView {
        tab: AgentTabSessionCapabilityV2,
        client_request_nonce: Nonce32,
        document: AgentMaskedDocumentRefV2,
        cursor: Option<AgentBrowserViewCursorCapabilityV2>,
        maximum_encoded_bytes: u32,
    } = 1,
    Act {
        tab: AgentTabSessionCapabilityV2,
        client_request_nonce: Nonce32,
        action: AgentBrowserActionV2,
    } = 2,
}

enum AgentBrowserExecutionStateV2 {
    Prepared = 1,
    Dispatching = 2,
    ResultGatePending = 3,
    Succeeded {
        document: AgentMaskedDocumentRefV2,
    } = 4,
    EffectSucceededOutputQuarantined {
        class: PublicFailureClassV2,
    } = 5,
    FailedNoEffect {
        class: PublicFailureClassV2,
    } = 6,
    Indeterminate = 7,
}

enum AgentBrowserReleaseStateV2 {
    Prepared = 1,
    Dispatching = 2,
    Succeeded = 3,
    EffectSucceededOutputQuarantined {
        class: PublicFailureClassV2,
    } = 4,
    FailedNoEffect {
        class: PublicFailureClassV2,
    } = 5,
    Indeterminate = 6,
}

enum AgentBrowserMutationResponseV2 {
    FollowupOpenIngress {
        post: FixedBrowserFormPostCarrierV2,
    } = 1,
    PlannerCommitted {
        steps: BoundedVec<AgentPlanStepRefV2, 256>,
    } = 2,
    ToolProposed {
        pending: AgentPendingToolCallRefV2,
    } = 3,
    ToolDenied {
        code: PublicStableCodeV2,
        trace: PublicDecisionTraceV2,
    } = 4,
    ToolOpenApproval {
        post: FixedBrowserFormPostCarrierV2,
        trace: PublicDecisionTraceV2,
    } = 5,
    ToolAuthorized {
        ticket: AgentExecutionTicketRefV2,
        trace: PublicDecisionTraceV2,
    } = 6,
    ExecutionDispatched {
        execution: AgentExecutionRefV2,
        state: PublicDispatchAcceptedStateV2,
    } = 7,
    ReleaseOpenApproval {
        post: FixedBrowserFormPostCarrierV2,
    } = 8,
    ReleaseDispatched {
        release: AgentReleaseRefV2,
        state: PublicDispatchAcceptedStateV2,
    } = 9,
    VaultRevoked {
        state: VaultPublicStateV2,
    } = 10,
    SessionClosed {
        state: AgentSessionStatusV2,
    } = 11,
    ExecutionRefreshed {
        execution: AgentExecutionRefV2,
        state: AgentBrowserExecutionStateV2,
    } = 12,
    ReleaseRefreshed {
        release: AgentReleaseRefV2,
        state: AgentBrowserReleaseStateV2,
    } = 13,
}

enum AgentBrowserObjectRefV2 {
    Document(AgentMaskedDocumentRefV2) = 1,
    PlanStep(AgentPlanStepRefV2) = 2,
    PendingToolCall(AgentPendingToolCallRefV2) = 3,
    ExecutionTicket(AgentExecutionTicketRefV2) = 4,
    ReleaseTicket(AgentReleaseTicketRefV2) = 5,
    Execution(AgentExecutionRefV2) = 6,
    Release(AgentReleaseRefV2) = 7,
}

struct AgentBrowserReadViewResponseV2 {
    view: AgentViewV2,
    objects: BoundedVec<AgentBrowserObjectRefV2, 4096>,
    next: Option<AgentBrowserViewCursorCapabilityV2>,
}
```

`FixedBrowserFormPostCarrierV2` is not a generic redirect or payload
container. Each tag compiles to one target and one form field:

| Carrier tag | Exact source origin | Exact target | Sole form field |
|---:|---|---|---|
| 1 | 8765 | `http://localhost:8767/v2/bootstrap/accept` | `transfer=<KernelIngressBootstrapTransferCapabilityV2>` |
| 2 | 8765 | `http://localhost:8766/v2/ui-auth/accept` | `transfer=<ApprovalDisplayAuthenticationTransferCapabilityV2>` |
| 3 | 8765 | `http://localhost:8766/v2/ui-auth/accept` | `transfer=<AgentUiAuthenticationTransferCapabilityV2>` |
| 4 | 8767 | `http://localhost:8766/v2/ui-auth/accept` | `transfer=<IngressUiAuthenticationTransferCapabilityV2>` |
| 5 | 8766 | `http://localhost:8767/v2/ui-auth/complete` | `transfer=<IngressUiAuthenticationSettlementTransferCapabilityV2>` |
| 6 | 8766 | `http://localhost:8768/v2/ui-auth/complete` | `transfer=<AgentUiAuthenticationSettlementTransferCapabilityV2>` |
| 7 | 8768 | `http://localhost:8767/v2/bootstrap/accept` | `transfer=<KernelIngressBootstrapTransferCapabilityV2>` |
| 8 | 8768 | `http://localhost:8766/v2/ui-auth/accept` | `transfer=<ApprovalDisplayAuthenticationTransferCapabilityV2>` |
| 9 | 8767 | `http://localhost:8766/v2/ui-auth/accept` | `transfer=<ApprovalDisplayAuthenticationTransferCapabilityV2>` |

The renderer accepts no URL, origin, path, status, field name, content type,
extra form field, redirect status, or opaque payload from a caller.
`UiActionV2` is internal service-to-service state and is never an HTTP
success body. Its rendering additionally fixes the emitting content origin:
ingressd `OpenApproval → tag 9`, agentd `OpenIngress → tag 7`, agentd
`OpenApproval → tag 8`; no other content-origin pair exists. The JARVIS
bootstrap mapping is independently `Ingress → tag 1`, `Approval → tag 2`,
`Agent → tag 3`, and ingress UI authentication alone uses tag 4.

The browser mutation projection is exhaustive:

| Origin/route + request variant | Exact success variant | HTTP status | Browser references | Replay identity |
|---|---|---:|---|---|
| 8765 bootstrap continue | exact one `JarvisBootstrapContinueTransferV2` form | 200 | no object ref | `(selector typed hash, client_request_nonce, canonical request)` |
| 8767 bootstrap accept | fixed wait shell plus carrier tag 4 | 200 | no object ref | one-way typed kernel-transfer tombstone |
| 8766 UI-auth accept, ingress/display/agent | fixed authentication shell with matching typed pre-auth capability | 200 | no object ref | one-way typed transfer tombstone |
| 8766 UI-auth begin, ingress/display/agent | matching `UiAuthenticationBrowserBeginResponseV2` variant | 200 | typed ceremony capability only | `(pre-auth typed hash, client_request_nonce, canonical variant)` |
| 8766 UI-auth finish, ingress/display/agent | matching `UiAuthenticationBrowserFinishResponseV2` variant | 200 | exact transfer or approval tab capability | `(ceremony typed hash, client_request_nonce, canonical variant)` |
| 8767 UI-auth complete | `IngressUiAuthenticationCompleteBrowserResponseV2` | 200 | ingress tab capability only | one-way typed settlement-transfer tombstone |
| 8768 UI-auth complete | `AgentUiAuthenticationCompleteBrowserResponseV2` | 200 | agent tab plus initial document ref | one-way typed settlement-transfer tombstone |
| 8766 approval decision begin | `ApprovalDecisionBrowserBeginResponseV2` | 200 | decision ceremony only | `(approval tab, client_request_nonce, canonical decision)` |
| 8766 approval decision finish | exactly `Denied` or `Approved` | 200 | none | `(decision ceremony typed hash, client_request_nonce, canonical assertion)` |
| 8766 enrollment begin | `BeginEnrollmentBrowserResponseV2` | 200 | enrollment ceremony only | `(enrollment handle typed hash, client_request_nonce, canonical request)` |
| 8766 enrollment finish | `FinishEnrollmentBrowserResponseV2` | 200 | none | `(enrollment ceremony typed hash, client_request_nonce, canonical request)` |
| 8767 input `Begin` | `IngressBrowserMutationResponseV2::Begun` | 200 | none | `(tab, client_request_nonce, canonical Begin)` |
| 8767 input `Append` | `ChunkAccepted` | 200 | none | `(tab, client_request_nonce, canonical Append)` |
| 8767 input `Finalize` | `FinalizeOpenApproval` with carrier tag 9 | 200 | no kernel handle | `(tab, client_request_nonce, canonical Finalize)` |
| 8767 input `Abort` | `Aborted` | 200 | none | `(tab, client_request_nonce, canonical Abort)` |
| 8768 view `ReadView` | `AgentBrowserReadViewResponseV2` | 200 | typed object refs and at most one typed cursor | `(tab, client_request_nonce, canonical ReadView)` |
| 8768 action `PrepareFollowupIngress` | `FollowupOpenIngress` with carrier tag 7 | 200 | no kernel handle | `(tab, client_request_nonce, canonical action)` |
| 8768 action `RunPlanner` | `PlannerCommitted` | 200 | fresh tab-bound step refs only | same |
| 8768 action `ProposePlanStep` | `ToolProposed` | 200 | fresh/existing pending ref only | same |
| 8768 action `EvaluatePending` | exactly one of `ToolDenied`, `ToolOpenApproval` tag 8, or `ToolAuthorized` | 200 | pending/ticket refs only | same |
| 8768 action `DispatchTicket` | `ExecutionDispatched` | 200 | one execution ref; state only Prepared/Dispatching | same |
| 8768 action `PrepareRelease` | `ReleaseOpenApproval` with carrier tag 8 | 200 | no kernel handle | same |
| 8768 action `DispatchRelease` | `ReleaseDispatched` | 200 | one release ref; state only Prepared/Dispatching | same |
| 8768 action `RefreshExecution` | `ExecutionRefreshed` | 200 | same execution ref; unique document ref only for tool success | same |
| 8768 action `RefreshRelease` | `ReleaseRefreshed` | 200 | same release ref; never a document ref | same |
| 8768 action `RevokeVault` | `VaultRevoked` | 200 | none | same |
| 8768 action `CloseSession` | `SessionClosed` | 200 | none | same |

For these mutation routes, an exact replay returns the byte-identical closed
success through section 10's capsule. `IdempotencyConflict` is fixed HTTP 409,
expired/restart-invalidated browser state is fixed HTTP 410, authentication or
origin failure closes without a body, and every other public failure is fixed
HTTP 400 with only `[PublicStableCodeV2]`. No success uses 3xx, a `Location`
header, a generic JSON/CBOR value, or a response variant assigned to another
row. Agent HTTP responses never expose `RunRevisionObservationV2`,
`RunRevisionDigestV2`, or any other run-revision digest.

`IngressTabSessionCapabilityV2` is a random 32-byte, tab-memory, new-input-only
capability minted only after `IngressInput` UI authentication. Its `Begin`
transition consumes the bound `IngressUiAuthorizationHandleV2`; no pre-auth
path accepts an input byte. Browser `Append` has no channel field: kerneld
selects `ChatText` for a stored `ChatText` session and `OriginalSource` for a
stored `PlainText` or `ParsedDocument` session. A browser can never select,
name, or encode `ExtractedPage`; that channel is accepted only through the
private parser-worker attestation path in section 9.2. Every `Agent*RefV2` is
a distinct unpredictable 16-byte per-tab non-capability reference derived by
the PRF below. Agentd emits it only in
the closed 8768 response variant that creates, reads, or refreshes that typed
local record: view may emit document/plan-step/pending/ticket refs; planner,
proposal, evaluation, and dispatch variants may emit only their named
step/pending/ticket/execution/release refs; refresh may repeat only the same
execution/release ref and create a document ref solely for tool success.
Agentd resolves a ref only for the matching action variant after the agent tab
capability and never puts the browser ref itself in a kernel request or
security digest. A reference of one object kind is rejected by every other
action decoder.

```rust
struct AgentdObjectRecordIdV2(FixedBytesV2<32>);

enum AgentdKernelObjectHandleBindingV2 {
    Document(MaskedDocumentHandleV2) = 1,
    PlanStep(PlanStepHandleV2) = 2,
    PendingToolCall(PendingToolCallHandleV2) = 3,
    ExecutionTicket(ExecutionTicketHandleV2) = 4,
    ReleaseTicket(ReleaseTicketHandleV2) = 5,
    Execution(ExecutionHandleV2) = 6,
    Release(ReleaseHandleV2) = 7,
}

enum AgentdBrowserObjectRecordStateV2 {
    Live = 1,
    ConsumedOrExpired = 2,
}

struct AgentdBrowserObjectRecordV2 {
    schema_version: u16,                 // exactly 2
    agentd_object_record_id: AgentdObjectRecordIdV2,
    agentd_boot_id: BootIdV2,
    tab_internal_id: Digest32,
    agent_ref_type_tag: u16,
    kernel_object_handle: AgentdKernelObjectHandleBindingV2,
    reference_binding_revision: u64,
    state: AgentdBrowserObjectRecordStateV2,
    resolver_typed_hash: Digest32,
}
```

`AgentdObjectRecordIdV2` is generated randomly by agentd for one typed local
mapping. It is never sent to kerneld or the browser. The mapping may retain
the already-issued opaque kernel handle, but it contains no kernel internal
object ID, semantic ID/digest, or bare handle hash that could be exposed as
the browser reference's meaning.
The delegated opaque handle is kept only in tab/agentd-boot-scoped
locked-memory zeroizing storage. It is never persisted, logged, audited,
exported, placed in a replay capsule, or copied into the browser-ref resolver
index; that index stores only the local record ID, ref digest/type/revision,
and typed hash. Destroying the tab or restarting agentd zeroizes the handle
and makes every associated browser ref invalid.

```text
AgentBrowserObjectRefV2 bytes =
  first_16_bytes(HMAC-SHA-256(
    agentd_tab_reference_key,
    "SAVANA_AGENT_BROWSER_OBJECT_REF_V2\0" ||
    canonical_cbor([
      agentd_boot_id,
      tab_internal_id,
      agent_ref_type_tag_u16,
      agentd_object_record_id,
      reference_binding_revision
    ])))
```

The per-tab reference key is CSPRNG-generated, locked-memory only, and
destroyed with the tab or agentd boot. Agentd stores only the typed hash
mapping and re-derives the same reference from that local record. The
immutable revision matrix is:

| Ref type | `reference_binding_revision` |
|---|---|
| document | immutable document issuance revision |
| plan step | immutable committed plan-step revision |
| pending tool call | issuance revision; resolver becomes unusable when consumed/terminal |
| execution ticket | issuance revision; resolver becomes unusable when consumed/expired |
| release ticket | issuance revision; resolver becomes unusable when consumed/expired |
| execution | immutable execution creation/dispatch identity revision |
| release | immutable release creation/dispatch identity revision |

Execution and release refresh updates only the returned state projection; it
never changes `reference_binding_revision`, rotates the ref, or creates a new
local object record. Pending/ticket state changes consume or expire their
resolver rather than deriving a new ref from mutable state. This applies to
all document, plan-step, pending, ticket, execution, and release refs and
cannot create a cross-type alias.

`KernelAgentViewCursorV2` is issued and consumed only by AgentKernel.
Agentd stores it behind a separately generated, hashed, tab-bound
`AgentBrowserViewCursorCapabilityV2`; the browser capability never enters a
kernel decoder, and the kernel cursor never enters an HTTP body. Reuse from
another tab, document, agentd boot, or cursor position is rejected before a
kernel call.

`DispatchTicket` and `DispatchRelease` return only a new typed execution or
release ref plus `Prepared/Dispatching`. `RefreshExecution` and
`RefreshRelease` are explicit replay-identified POST mutations that resolve
those refs and call only AgentKernel operation 30 or 35 respectively. A tool
success maps the already emitted kernel document handle to the unique
document ref for that tab/object revision; release success has no document.
`RefreshExecution` uses only `AgentBrowserExecutionStateV2` and therefore a
success always has one tool document. `RefreshRelease` uses only
`AgentBrowserReleaseStateV2`; it has no `ResultGatePending` or document
variant. Operation 35 likewise rejects `ResultGatePending` and every
tool-success branch as a noncanonical release status.
There is no SSE, implicit polling route, URL reference, JARVIS status bridge,
or background response channel.

All browser capabilities are returned only in the body of the POST that
created them, retained only in JavaScript memory, stored hashed server-side,
and bound to exact origin, purpose, task/internal preparation, principal,
manifest, daemon boot, tab lineage, and expiry. They never enter a URL,
fragment, cookie, authorization header, referrer, log, HTML cache,
`localStorage`, `sessionStorage`, IndexedDB, Cache API, or service worker.
Navigation, close, logout, expiry, restart, consumption, or first binding
mismatch invalidates them. All POST decoders reject extra fields, duplicate
JSON keys, alternate media types, chunked transfer, and content beyond the
compiled ceiling.

Enrollment begin atomically verifies and consumes the exact
`(EnrollmentHandleV2, code)` pair, creates a fresh WebAuthn `create`
challenge, and returns a random, hashed-at-rest, port-8766-bound
`EnrollmentCeremonyCapabilityV2` only in the POST body. Finish consumes that
capability once and accepts only the credential ID, exact client-data JSON,
and exact attestation object bound to the stored creation options. Failure,
expiry, restart, or replay cannot restore the enrollment code or ceremony
capability.

## 6. Data-bearing types

### 6.1 Kernel values

```rust
enum KernelValueV2 {
    Null,
    Bool(bool),
    I64(i64),
    Text(ZeroizingTextV2),
    Bytes(ZeroizingBytesV2),
    List(BoundedVec<KernelValueV2, 65_536>),
    Object(BoundedSortedVec<(FieldNameV2, KernelValueV2), 65_536>),
    InternalSlot(InternalSlotDigestV2),
}
```

Objects use strictly increasing canonical field order. Duplicate names fail.
Content-bearing variants do not implement `Clone` or content-bearing `Debug`.

### 6.2 Agent view

```rust
struct ActiveToolViewV2 {
    tool: ToolHandleV2,
    action_template: ActionTemplateIdV2,
    tool_class: ToolClassIdV2,
    display_template: StaticTemplateIdV2,
}

struct PlaceholderViewV2 {
    ordinal: u32,
    token: BoundedText1024V2,
    redaction_class: ClosedRedactionClassV2,
}

struct AgentViewFieldV2 {
    name: FieldNameV2,
    text: ZeroizingTextV2,
    placeholders: BoundedVec<PlaceholderViewV2, 20_000>,
}

struct PublicDecisionTraceV2 {
    decision_record_digest: Digest32,
}

enum AgentContentStateV2 {
    Ready = 1,
    Running = 2,
    AwaitingApproval = 3,
    Closed = 4,
    Failed = 5,
    Indeterminate = 6,
}
```

`ActiveToolViewV2` entries are strictly increasing by
`(action_template, tool_class, canonical(tool))` and duplicate handles are
rejected. Placeholder ordinals start at zero, are contiguous within one text
value, and each token must occur in that text. `PublicDecisionTraceV2` is only
a non-authorizing commitment to the private decision record; it contains no
rule text, producer reason, validator output, data digest, or capability.

`AgentViewV2` is a closed union of:

```rust
enum AgentViewV2 {
    MaskedText {
        text: ZeroizingTextV2,
        placeholders: BoundedVec<PlaceholderViewV2, 20_000>,
    },
    Structured {
        template: StaticTemplateIdV2,
        fields: BoundedVec<AgentViewFieldV2, 256>,
    },
    DocumentPage {
        page_index: u32,
        text: ZeroizingTextV2,
        placeholders: BoundedVec<PlaceholderViewV2, 20_000>,
    },
    ContentState(AgentContentStateV2),
}
```

Only kerneld constructs it after a signed declassification rule and mandatory
leak gate. It is valid only for the agent reader and agentd browser origin.
`AgentContentStateV2` contains no public task handle, JARVIS bootstrap action,
selector, or agentd-owned status.

### 6.3 Abstract planner envelope

```rust
struct PlannerEnvelopeV2 {
    schema_version: u16,
    planner_route: PlannerRouteIdV2,
    task_template: StaticTemplateIdV2,
    intent: IntentKindV2,
    allowed_action_templates: BoundedVec<ActionTemplateIdV2, 256>,
    slots: BoundedVec<AbstractSlotV2, 256>,
    relations: BoundedVec<AbstractRelationV2, 512>,
    effective_limits: PlannerLimitsV2,
    envelope_nonce: Nonce32,
    expires_at: UnixMillis,
}

struct AbstractSlotV2 {
    reference: PlannerSlotRefV2,
    kind: SlotKindV2,
    cardinality: ClosedCardinalityV2,
    confidentiality: PlannerSlotConfidentialityV2,
    permitted_relations: ClosedRelationSetV2,
}

struct ClosedRelationSetV2(BoundedSortedVec<RelationIdV2, 64>);

struct AbstractRelationV2 {
    relation: RelationIdV2,
    left: PlannerSlotRefV2,
    right: PlannerSlotRefV2,
}

struct PlannerLimitsV2 {
    maximum_steps: u16,
    maximum_dependencies_per_step: u16,
    maximum_arguments_per_step: u16,
    maximum_encoded_plan_bytes: u32,
}
```

No variant contains generic text, bytes, arbitrary source-derived numbers,
filename, destination, query, topic, contact, content, raw digest, or concrete
slot value.

```rust
struct PlannerPlanV2 {
    schema_version: u16,
    envelope_nonce: Nonce32,
    steps: BoundedVec<PlannerStepV2, 256>,
}

struct PlannerStepV2 {
    ordinal: u16,
    action_template: ActionTemplateIdV2,
    tool_class: ToolClassIdV2,
    slot_bindings: BoundedSortedVec<(ArgumentNameV2, PlannerSlotRefV2), 256>,
    dependencies: BoundedSortedVec<u16, 256>,
}

struct ResolvedPlannerSlotV2 {
    slot_ordinal: u16,
    kind: SlotKindV2,
    cardinality: ClosedCardinalityV2,
    confidentiality: PlannerSlotConfidentialityV2,
    permitted_relations: ClosedRelationSetV2,
    value_internal_id: ValueInternalIdV2,
    value_digest: Digest32,
    provenance_digest: Digest32,
    relation_semantics_digest: Digest32,
    internal_slot_digest: InternalSlotDigestV2,
}

struct ResolvedPlannerEnvelopeV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    planner_route: PlannerRouteIdV2,
    task_template: StaticTemplateIdV2,
    intent: IntentKindV2,
    allowed_action_templates: BoundedVec<ActionTemplateIdV2, 256>,
    slots: BoundedVec<ResolvedPlannerSlotV2, 256>,
    relations_by_slot_ordinal:
        BoundedVec<(RelationIdV2, u16, u16), 512>,
    effective_limits: PlannerLimitsV2,
}

struct ResolvedPlannerStepV2 {
    ordinal: u16,
    action_template: ActionTemplateIdV2,
    tool_class: ToolClassIdV2,
    argument_bindings:
        BoundedSortedVec<ResolvedPlannerArgumentBindingV2, 256>,
    dependency_ordinals: BoundedSortedVec<u16, 256>,
}

struct ResolvedPlannerArgumentBindingV2 {
    argument_name: ArgumentNameV2,
    internal_slot_digest: InternalSlotDigestV2,
    value_internal_id: ValueInternalIdV2,
    value_digest: Digest32,
    provenance_digest: Digest32,
}

struct ResolvedSlotRelationSemanticV2 {
    relation: RelationIdV2,
    left_slot_ordinal: u16,
    right_slot_ordinal: u16,
}

struct ResolvedPlannerPlanV2 {
    schema_version: u16,                 // exactly 2
    resolved_envelope: ResolvedPlannerEnvelopeV2,
    steps: BoundedVec<ResolvedPlannerStepV2, 256>,
}
```

`PlannerSlotRefV2` is a random 16-byte, per-envelope, non-authorizing
reference. It is accepted only while validating the exact
`(PlannerTicketHandleV2, envelope_nonce)` pair and has no public resolver.
kerneld stores a private mapping from each reference to one
`InternalSlotDigestV2`:

```text
SlotRelationSemanticsDigest[slot_ordinal] =
  SHA-256("SAVANA_SLOT_RELATION_SEMANTICS_V2\0" ||
          canonical_cbor(
            BoundedSortedVec<ResolvedSlotRelationSemanticV2, 512>
            containing every relation incident to slot_ordinal))

InternalSlotDigest =
  SHA-256("SAVANA_INTERNAL_SLOT_V2\0" ||
          canonical_cbor([
            installation_id,
            active_state_manifest_digest,
            durable_run_id,
            slot_ordinal,
            kind,
            cardinality,
            confidentiality,
            permitted_relations,
            value_internal_id,
            value_digest,
            provenance_digest,
            SlotRelationSemanticsDigest[slot_ordinal]
          ]))
```

Neither `PlannerSlotRefV2` nor any capability handle enters a value,
provenance, argument, plan-revision, action-intent, approval, destination, or
dispatch security digest. The planner cannot mint a slot, template, tool,
ordinal duplicate, or dependency cycle. kerneld derives internal immutable
plan-step IDs after validation. Planner commit creates no action intent.

After validating the exact wire envelope/plan pair, kerneld resolves every
slot reference through the private ticket map and constructs
`ResolvedPlannerEnvelopeV2` and `ResolvedPlannerPlanV2`. Those canonical
objects contain no `PlannerSlotRefV2`, handle, request ID, envelope nonce, or
transport digest. Slot order is the original canonical envelope ordinal;
relations use those checked ordinals. Each argument binding repeats the
resolved slot's `InternalSlotDigestV2`, stable value internal ID, value
digest, and provenance digest.
Every repeated value/provenance tuple must byte-equal the stored immutable
record. Kerneld recomputes every relation-semantics and internal-slot digest
from the handle-free resolved envelope before it accepts a step binding.
`PlannerEnvelopeDigest`, envelope nonce, and wire slot reference are absent
from the formula and cannot perturb semantic identity.

```text
ResolvedPlannerEnvelopeDigest =
  SHA-256("SAVANA_RESOLVED_PLANNER_ENVELOPE_V2\0" ||
          canonical_cbor(ResolvedPlannerEnvelopeV2))

PlanRevisionDigest =
  SHA-256("SAVANA_RESOLVED_PLANNER_PLAN_V2\0" ||
          canonical_cbor(ResolvedPlannerPlanV2))

InternalStepId[ordinal] =
  SHA-256("SAVANA_INTERNAL_PLAN_STEP_V2\0" ||
          durable_run_id ||
          PlanRevisionDigest ||
          ordinal_u16be ||
          SHA-256("SAVANA_RESOLVED_PLANNER_STEP_V2\0" ||
                  canonical_cbor(ResolvedPlannerStepV2[ordinal])))
```

The wire `PlannerEnvelopeDigest` and `PlannerWireOutputDigest` remain
transcript/root-evidence digests proving what the external planner saw and
returned. Because they contain random wire references/nonces, neither is a
semantic plan, action, approval, dispatch, or deduplication digest. Semantic
authorization uses only `ResolvedPlannerEnvelopeDigest`,
`PlanRevisionDigestV2`, and `InternalStepIdV2`.

### 6.4 Data enum tags and closed identifier ABI

The data-bearing discriminants used in wire bytes and semantic digests are:

```text
KernelValueV2
0 Null, 1 Bool, 2 I64, 3 Text, 4 Bytes, 5 List, 6 Object,
7 InternalSlot

AgentViewV2
1 MaskedText, 2 Structured, 3 DocumentPage, 4 ContentState

SourceKindV2
1 GatedIngress, 2 KernelExtraction, 3 PolicyConstant, 4 PlannerOutput,
5 ToolResult, 6 Derived, 7 KernelDeclassification, 8 RecoveredExecution

DeriveOperationV2
1 ConcatenateText, 2 NormalizeNfc, 3 SelectObjectField,
4 AssembleList, 5 AssembleObject, 6 PolicyConstant

OntologyScalarV2
0 Null, 1 Bool, 2 I64, 3 Text, 4 Digest

OntologyOperandV2
1 Argument, 2 Ontology, 3 Context, 4 Literal

ContextFieldV2
1 Role, 2 Tool, 3 AttemptKind, 4 PrincipalDigest, 5 TaskDigest

OntologyExprV2
1 Eq, 2 Ne, 3 In, 4 NotIn, 5 All, 6 Any

ProjectionExprV2
1 Argument, 2 PolicyConstant, 3 Object, 4 List

DisplayExprV2
1 Select, 2 Mask, 3 Label, 4 Object, 5 List

MaskKindV2
1 Email, 2 Phone, 3 Host, 4 Path, 5 TextPrefixSuffix,
6 TokenCount, 7 DigestOnly

IngressSubjectV2
1 NewRun, 2 ExistingRun

ContentKindV2
1 ChatText, 2 PlainText, 3 ParsedDocument

InputSourceKindV2
1 Chat, 2 Paste, 3 FileUpload

InputSourceProvenanceV2
1 Direct, 2 ParsedDocument

ClosedCardinalityV2
1 ExactlyOne, 2 ZeroOrOne, 3 OneOrMore, 4 ZeroOrMore

PlannerSlotConfidentialityV2
1 PublicStructural, 2 ConfidentialAbstract

ExecutorIdempotencyContractV2
1 ConnectorIdempotentByExecutionNonce,
2 ConnectorNonIdempotentSingleAttempt
```

`IntentKindV2`, `SlotKindV2`, role IDs, relation IDs, template IDs,
action-template IDs, tool-class IDs, planner-route IDs, ontology
namespace/entity/set IDs,
projection IDs, policy-constant IDs, implementation IDs, enrollment-profile
IDs, attempt-kind IDs, and closed media/extension/confidence/redaction/reason
IDs are canonical unsigned u32 newtypes. Their allowed values and meanings are
a finite set in the exact active manifest lock; an unlisted value is rejected
and cannot be interpreted as an extension. `RelationIdV2` is the relation-ID
newtype used by `AbstractRelationV2`.

`IdentifierV2`, `FieldNameV2`, and `ArgumentNameV2` are 1–128-byte NFC text
matching ASCII `[A-Za-z][A-Za-z0-9_.-]*`. `VersionV2` is exactly
`[major_u16, minor_u16, patch_u16]`. `PrincipalIdV2`,
`JarvisPrincipalIdV2`,
`ServiceIdentityV2`, `ExecutorIdentityV2`, `DurableTaskIdV2`,
`DurableRunIdV2`, `DurableReleaseIdV2`, `ValueInternalIdV2`,
`InternalStepIdV2`, `RunRevisionDigestV2`, and `PlanRevisionDigestV2`,
internal record IDs, and producer identities are distinct 32-byte digest
newtypes. No generic string, untyped `Digest32`, or integer is accepted for
them.

## 7. G3 security labels and provenance

### 7.1 Labels

```rust
enum IntegrityV2 {
    KernelTrusted = 1,
    UserAuthorized = 2,
    ExternalUntrusted = 3,
}
```

The order is:

```text
KernelTrusted < UserAuthorized < ExternalUntrusted
```

Normal derivation takes the maximum, so integrity never improves.

```rust
enum ConfidentialityV2 {
    Public = 1,
    PlannerAbstract = 2,
    AgentMasked = 3,
    VaultBound = 4,
}
```

Confidentiality is the diamond lattice:

```text
                    VaultBound
                   /          \
       PlannerAbstract        AgentMasked
                   \          /
                       Public
```

`PlannerAbstract` and `AgentMasked` are incomparable. The join table is:

| `∨` | Public | PlannerAbstract | AgentMasked | VaultBound |
|---|---|---|---|---|
| Public | Public | PlannerAbstract | AgentMasked | VaultBound |
| PlannerAbstract | PlannerAbstract | PlannerAbstract | VaultBound | VaultBound |
| AgentMasked | AgentMasked | VaultBound | AgentMasked | VaultBound |
| VaultBound | VaultBound | VaultBound | VaultBound | VaultBound |

Normal derivation takes this join over every parent, so combining
planner-abstract and agent-masked data becomes `VaultBound`; it is never
implicitly readable by either branch.

```rust
bitflags ReaderSetV2 {
    KERNEL           = 0x0001
    AGENT            = 0x0002
    INGRESS          = 0x0004
    APPROVAL_DISPLAY = 0x0008
    EXECUTOR         = 0x0010
    EXTERNAL_PLANNER = 0x0020
    EXTERNAL_SINK    = 0x0040
}
```

There is no JARVIS reader. Normal derivation intersects parent reader sets.

```rust
bitflags EffectSetV2 {
    READ          = 0x0001
    CREATE        = 0x0002
    UPDATE        = 0x0004
    DELETE        = 0x0008
    SEND          = 0x0010
    EXECUTE       = 0x0020
    FINAL_RELEASE = 0x0040
}
```

Normal derivation intersects parent effects with the signed policy allowance.

Only these private kernel transitions may declassify or widen readers:

```text
MaskTokenizeAndLeakCheck  → AgentMasked / AGENT
BuildPlannerEnvelope      → PlannerAbstract / EXTERNAL_PLANNER
BuildApprovalDisplay      → AgentMasked / APPROVAL_DISPLAY
BuildExecutionEnvelope    → VaultBound / one exact EXECUTOR
BuildFinalRelease         → VaultBound / one exact EXTERNAL_SINK
```

Each creates a new provenance node binding the rule, implementation, input and
output digests, token set, leak-gate identity, purpose, reader, expiry, and
active state manifest. Public `DeriveValue` has no declassification variant.

### 7.2 Sources

```rust
enum SourceKindV2 {
    GatedIngress { settlement_digest: Digest32 },
    KernelExtraction { model_digest: Digest32, schema_digest: Digest32 },
    PolicyConstant { constant_id: PolicyConstantIdV2 },
    PlannerOutput { planner_route_digest: Digest32 },
    ToolResult { action_intent: ActionIntentIdV2,
                 execution_nonce_digest: Digest32 },
    Derived { operation: DeriveOperationV2 },
    KernelDeclassification { rule_digest: Digest32 },
    RecoveredExecution { dispatch_record_digest: Digest32 },
}
```

Planner and tool results are always `ExternalUntrusted`.

Every source has one exact initial label and parent rule:

| Source | Integrity | Confidentiality | Initial readers | Parents/root evidence |
|---|---|---|---|---|
| `GatedIngress` | `UserAuthorized` | `VaultBound` | `KERNEL` | no value parent; exact ingress settlement, source, and approval digests are roots |
| `KernelExtraction` | join of its ingress parents; never better than `UserAuthorized` | join of parents | intersection of parents, initially `KERNEL` | at least one gated-ingress parent plus model/schema roots |
| `PolicyConstant` | `KernelTrusted` | the signed constant's declared lattice value | signed constant readers intersected with policy | no value parent; signed policy constant is a root |
| `PlannerOutput` | `ExternalUntrusted` | `PlannerAbstract` until re-bound into a kernel value, then join with referenced slots | `KERNEL` | exact planner envelope/output and every referenced internal-slot provenance are parents/roots |
| `ToolResult` | `ExternalUntrusted` | `VaultBound` | `KERNEL` | action intent, execution nonce, descriptor, executor receipt, and result digest are roots |
| `Derived` | maximum integrity of all parents | confidentiality join of all parents | intersection of all parents | one or more ordered parents; zero-parent derivation is forbidden |
| `KernelDeclassification` | never better than the maximum parent integrity | exact signed target allowed by the named private transition | exact purpose reader only | all input values plus rule/implementation/leak-gate roots |
| `RecoveredExecution` | `ExternalUntrusted` | `VaultBound` | `KERNEL` | durable dispatch, execd journal head, receipt, and result digest are roots |

Every source also starts with the effect set explicitly allowed by signed
policy; absent policy means the empty set. Initial labels are created in the
same atomic transaction as value bytes, provenance, root evidence, and the
first handle. A source record with a missing required parent/root, a parent
from another run/manifest, or any caller-provided initial label is rejected.

Every value stores sorted unique root-evidence digests, maximum 64. Derivation
uses set union and fails on overflow. It never replaces lost members with one
aggregate that prevents later membership checks.

### 7.3 Digest domains

```rust
struct ArgumentDigestEntryV2 {
    argument_name: ArgumentNameV2,
    value_internal_id: ValueInternalIdV2,
    value_digest: Digest32,
    provenance_digest: Digest32,
}

struct ProvenanceSetDigestEntryV2 {
    value_internal_id: ValueInternalIdV2,
    value_digest: Digest32,
    provenance_digest: Digest32,
}

struct TokenSetDigestEntryV2 {
    token_slot_id: IdentifierV2,
    vault_segment_internal_id: Digest32,
    credential_version_digest: Digest32,
    executor_identity_digest: Digest32,
}
```

```text
ValueDigest =
  SHA-256("SAVANA_VALUE_V2\0" ||
          canonical_cbor(KernelValueV2))

ProvenanceDigest =
  SHA-256("SAVANA_PROVENANCE_V2\0" ||
          canonical_cbor([
            source_kind,
            producer_identity_digest,
            value_digest,
            ordered_parent_value_digests,
            ordered_parent_provenance_digests,
            sorted_root_evidence_digests,
            integrity,
            confidentiality,
            reader_set,
            effect_set,
            run_internal_id,
            active_state_manifest_digest,
            created_at,
            expires_at
          ]))

ArgumentDigest =
  SHA-256("SAVANA_ARGUMENTS_V2\0" ||
          canonical_cbor(
            BoundedSortedVec<ArgumentDigestEntryV2, 256>))

ProvenanceSetDigest =
  SHA-256("SAVANA_PROVENANCE_SET_V2\0" ||
          canonical_cbor(
            BoundedSortedVec<ProvenanceSetDigestEntryV2, 256>))

EvidenceDigest =
  SHA-256("SAVANA_EVIDENCE_V2\0" ||
          canonical_cbor(sorted [
            value_digest,
            provenance_digest
          ]))

TokenSetDigest =
  SHA-256("SAVANA_TOKEN_SET_V2\0" ||
          canonical_cbor([
            item_count,
            BoundedSortedVec<TokenSetDigestEntryV2, 64>
          ]))

PlannerEnvelopeDigest =
  SHA-256("SAVANA_PLANNER_ENVELOPE_V2\0" ||
          canonical_cbor(PlannerEnvelopeV2))

PlannerWireOutputDigest =
  SHA-256("SAVANA_PLANNER_WIRE_OUTPUT_V2\0" ||
          canonical_cbor(PlannerPlanV2))
```

No capability handle, `TaskHandleV2`, browser/session token,
`PlannerSlotRefV2`, planner envelope nonce, request ID, or transport sequence
enters a semantic security digest. `PlannerEnvelopeDigest` and
`PlannerWireOutputDigest` may contain those wire references only as
transcript/root evidence and are forbidden wherever a semantic plan revision,
step, argument, action, approval, dispatch, WAL, or deduplication identity is
required. Kernel-internal stable IDs, `InternalSlotDigestV2`, and
content/provenance digests do enter semantic digests. The canonical argument
list is strictly increasing by `ArgumentNameV2` NFC UTF-8 bytes and contains
exactly one four-element array per argument; duplicate names are rejected
before hashing.
The provenance set is strictly increasing by
`(value_internal_id, value_digest, provenance_digest)`, contains exactly the
values in the argument binding, and rejects duplicate internal IDs or a stored
record mismatch.
The evidence list is strictly increasing by `(value_digest,
provenance_digest)`. The token-set list is strictly increasing by
`token_slot_id`; it contains stable internal vault/credential identities,
never token bytes or a capability handle. Its encoded `item_count` equals the
vector length, and every `executor_identity_digest` recomputes from the exact
bound executor identity. Duplicate slot IDs, unknown slots, or mismatched
vault/credential/executor records are rejected.

Parent records may be collected only after their immutable value,
provenance, root-evidence, and descendant-reference tombstones remain until
the last descendant and action retention deadline.

## 8. Closed derivation, ontology, projection, and descriptor languages

### 8.1 Derivation

```rust
enum DeriveOperationV2 {
    ConcatenateText,
    NormalizeNfc,
    SelectObjectField(ArgumentNameV2),
    AssembleList,
    AssembleObject(BoundedVec<ArgumentNameV2, 256>),
    PolicyConstant(PolicyConstantIdV2),
}
```

There is no caller-supplied literal constant. Type error, missing field,
Unicode error, overflow, limit, allocation, or digest failure changes no
state.

### 8.2 Ontology

```rust
enum OntologyScalarV2 {
    Null,
    Bool(bool),
    I64(i64),
    Text(BoundedText1024V2),
    Digest(Digest32),
}

struct FieldPathV2(BoundedVec<FieldNameV2, 16>);

enum OntologyOperandV2 {
    Argument { name: ArgumentNameV2, path: FieldPathV2 },
    Ontology { namespace: NamespaceIdV2,
               entity: EntityIdV2,
               path: FieldPathV2 },
    Context(ContextFieldV2),
    Literal(OntologyScalarV2),
}

enum ContextFieldV2 {
    Role,
    Tool,
    AttemptKind,
    PrincipalDigest,
    TaskDigest,
}

struct ManifestOntologySetRefV2 {
    namespace: NamespaceIdV2,
    set: OntologySetIdV2,
    set_digest: Digest32,
}

enum OntologyExprV2 {
    Eq(OntologyOperandV2, OntologyOperandV2),
    Ne(OntologyOperandV2, OntologyOperandV2),
    In(OntologyOperandV2, ManifestOntologySetRefV2),
    NotIn(OntologyOperandV2, ManifestOntologySetRefV2),
    All(BoundedVec<OntologyExprV2, 32>),
    Any(BoundedVec<OntologyExprV2, 32>),
}
```

`ManifestOntologySetRefV2` is a closed manifest-bound reference whose three
fields must match one signed ontology-set entry byte-for-byte; callers cannot
supply literal set members or a dynamic path. Depth is at most 8 and total
nodes at most 256.
`All`/`Any` have 1–32 children. There is no float, coercion, regex, arithmetic,
dynamic namespace, or code. Missing path, type mismatch, unknown namespace or
set, digest mismatch, or resource error is `EvaluationError`; both false and
error deny, while private audit distinguishes them.

### 8.3 Destination and display projection

```rust
struct ProjectionFieldV2 {
    name: FieldNameV2,
    value: ProjectionExprV2,
}

enum ProjectionExprV2 {
    Argument { name: ArgumentNameV2, path: FieldPathV2 },
    PolicyConstant(PolicyConstantIdV2),
    Object(BoundedVec<ProjectionFieldV2, 64>),
    List(BoundedVec<ProjectionExprV2, 64>),
}

struct DisplayFieldV2 {
    name: FieldNameV2,
    value: DisplayExprV2,
}

enum DisplayExprV2 {
    Select(ProjectionExprV2),
    Mask { input: ProjectionExprV2, kind: MaskKindV2 },
    Label(PolicyConstantIdV2),
    Object(BoundedVec<DisplayFieldV2, 64>),
    List(BoundedVec<DisplayExprV2, 64>),
}

enum MaskKindV2 {
    Email,
    Phone,
    Host,
    Path,
    TextPrefixSuffix { prefix_chars: u8, suffix_chars: u8 },
    TokenCount,
    DigestOnly,
}
```

Projection/display object fields are strictly increasing by `FieldNameV2`
canonical bytes and duplicate names are rejected.

Destination output must satisfy the descriptor destination schema. Display
may read only destination-read fields or explicitly approved digest/count
fields. Missing/type error denies.

```text
DestinationDigest =
  SHA-256("SAVANA_DESTINATION_V2\0" ||
          destination_projection_digest ||
          canonical_cbor(projected_destination_value))

DisplayDigest =
  SHA-256("SAVANA_DISPLAY_V2\0" ||
          display_projection_digest ||
          canonical_cbor(projected_display_value))
```

Approval binds both projection identities and both output digests.
Both projected values use `KernelValueV2` canonical encoding with
`InternalSlot` forbidden; display rendering occurs only after the digest is
verified.

### 8.4 Tool descriptors and validators

```rust
enum ExecutorIdempotencyContractV2 {
    ConnectorIdempotentByExecutionNonce = 1,
    ConnectorNonIdempotentSingleAttempt = 2,
}

enum AttemptKindV2 {
    ToolRead = 1,
    ToolWrite = 2,
    ToolIrreversible = 3,
}

struct BoundedConnectorRetryPolicyV2 {
    maximum_attempts: u16,
    maximum_elapsed_ns: u64,
}

struct UnsignedToolDescriptorV2 {
    schema_version: u16,                 // exactly 2
    registry_version: VersionV2,
    provider_identity_digest: Digest32,
    provider_tool_id: IdentifierV2,
    action_template: ActionTemplateIdV2,
    tool_class: ToolClassIdV2,
    argument_schema_digest: Digest32,
    result_schema_digest: Digest32,
    allowed_roles: BoundedSortedVec<RoleIdV2, 64>,
    effects: EffectSetV2,
    attempt_kind: AttemptKindV2,
    connector_retry_policy: BoundedConnectorRetryPolicyV2,
    internal_validators:
        BoundedVec<InternalValidatorDeclarationV2, 32>,
    executor_identity: ExecutorIdentityV2,
    destination_projection: ProjectionIdV2,
    destination_projection_digest: Digest32,
    display_projection: DisplayProjectionIdV2,
    display_projection_digest: Digest32,
    idempotency_contract: ExecutorIdempotencyContractV2,
    not_before: UnixMillis,
    expires_at: UnixMillis,
}
```

`ConnectorNonIdempotentSingleAttempt` requires
`maximum_attempts = 1` and `maximum_elapsed_ns = 0`.
`ConnectorIdempotentByExecutionNonce` requires `maximum_attempts` in
`1..=8` and `maximum_elapsed_ns` in `1..=30_000_000_000`; the manifest may
compile stricter bounds. No default or omitted retry policy exists.

```text
DescriptorDigest =
  SHA-256("SAVANA_TOOL_DESCRIPTOR_V2\0" ||
          canonical_cbor(UnsignedToolDescriptorV2))

DescriptorSignature =
  Ed25519.sign(registry_publisher_key,
               "SAVANA_TOOL_DESCRIPTOR_SIGNATURE_V2\0" ||
               DescriptorDigest)
```

The descriptor excludes publisher-supplied digest evidence and signature,
preventing self-reference. `allowed_roles` is strictly increasing by
`RoleIdV2`. `internal_validators` is strictly increasing by
`(implementation_id, semantic_version, build_manifest_digest)` with no
duplicate implementation ID.
`SignedToolDescriptorV2` is
`[unsigned_descriptor_payload_bstr, publisher_key_id,
DescriptorSignature]` under section 3.1. Registry activation verifies the
exact publisher key/domain and stores the descriptor digest; runtime requests
carry only a boot-bound `ToolHandleV2` resolved to that immutable record.

V2 suite 1 permits internal validators only:

```rust
struct InternalValidatorDeclarationV2 {
    implementation_id: ImplementationIdV2,
    semantic_version: VersionV2,
    build_manifest_digest: Digest32,
}
```

Internal digests come from the reproducible build-generated validator manifest
bound by the active security-state manifest. There is no external validator
declaration, attestation DTO, validator key, network endpoint, caller-provided
verdict, or public producer reason in initial V2. `EvaluateToolCall` invokes
the exact required internal validator set itself; missing, version/digest
mismatch, crash, timeout, or resource failure denies.

## 9. Ingress subject and source provenance

### 9.1 Subject without circular identity

```rust
enum RunRevisionTransitionKindV2 {
    Genesis = 1,
    InputCommitted = 2,
    PlannerCommitted = 3,
    ValueDerived = 4,
    IntentCreated = 5,
    ResultCommitted = 6,
    VaultStateChanged = 7,
    SessionClosed = 8,
}

struct CommittedInputSetItemV2 {
    input_ordinal: u32,
    ingress_subject_digest: Digest32,
    input_commit_digest: Digest32,
}

struct ValueProvenanceSetItemV2 {
    value_internal_id: ValueInternalIdV2,
    value_digest: Digest32,
    provenance_digest: Digest32,
}

struct ActionStateSetItemV2 {
    action_intent_id: ActionIntentIdV2,
    projection_version: u64,
    current_state_tag: u16,
    state_payload_digest: Digest32,
}

struct VaultStateSetItemV2 {
    vault_segment_internal_id: Digest32,
    state_revision: u64,
    state_tag: u16,
    vault_state_record_digest: Digest32,
}

struct ActiveToolSetItemV2 {
    tool_descriptor_digest: Digest32,
    tool_registry_ordinal: u32,
    tool_policy_activation_digest: Digest32,
}

struct InputValueProvenanceSetItemV2 {
    value_internal_id: ValueInternalIdV2,
    value_digest: Digest32,
    provenance_digest: Digest32,
    ingress_subject_digest: Digest32,
}

struct RunRevisionV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    revision_number: u64,
    previous_revision_digest: Option<RunRevisionDigestV2>,
    transition_kind: RunRevisionTransitionKindV2,
    transition_subject_digest: Digest32,
    transition_advance_digest: Digest32,
    committed_input_set_digest: Digest32,
    value_provenance_set_digest: Digest32,
    active_plan_revision_digest: Option<PlanRevisionDigestV2>,
    action_state_set_digest: Digest32,
    vault_state_set_digest: Digest32,
}

struct RunRevisionObservationV2 {
    durable_run_id: DurableRunIdV2,
    revision_number: u64,
    revision_digest: RunRevisionDigestV2,
}

struct PendingAgentClaimBindingV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    durable_task_id: DurableTaskIdV2,
    authenticated_principal: PrincipalIdV2,
    expected_agentd_identity: ServiceIdentityV2,
    ingress_settlement_digest: Digest32,
    binding_nonce: Nonce32,
    claim_expires_at: UnixMillis,
}

struct UnredeemableAgentClaimCommitmentV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    committed_manifest_digest: Digest32,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    authenticated_principal: PrincipalIdV2,
    expected_agentd_identity: ServiceIdentityV2,
    committed_run_revision_digest: RunRevisionDigestV2,
    ingress_settlement_digest: Digest32,
    input_value_provenance_set_digest: Digest32,
    initial_value_internal_id: ValueInternalIdV2,
    initial_document_internal_id: Digest32,
    vault_segment_internal_id: Digest32,
    active_tool_set_digest: Digest32,
    non_authorizing_record_nonce: Nonce32,
    claim_expires_at: UnixMillis,
}

enum PendingAgentClaimBindingTombstoneReasonV2 {
    ConsumedIntoClaimCommitment = 1,
    Denied = 2,
    Aborted = 3,
    Expired = 4,
    FailedClosed = 5,
    RestartInvalidated = 6,
}

struct PendingAgentClaimBindingTombstoneV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    durable_task_id: DurableTaskIdV2,
    pending_binding_digest: Digest32,
    reason: PendingAgentClaimBindingTombstoneReasonV2,
    derived_claim_commitment_digest: Option<Digest32>,
    terminal_transaction_digest: Digest32,
    tombstoned_at: UnixMillis,
}

enum RestartInvalidatedPriorInputStateV2 {
    Granted = 1,
    Receiving = 2,
    Finalizing = 3,
    AwaitingApproval = 4,
    Committing = 5,
    CommittedUnclaimed = 6,
    AgentAuthPending = 7,
}

enum RestartInvalidatedDispositionV2 {
    PreCommitStagingCleared {
        pending_binding_tombstone_digest: Digest32,
        staging_clear_receipt_digest: Digest32,
    } = 1,
    CommittedClaimRetainedByPolicy {
        claim_commitment_digest: Digest32,
        vault_segment_internal_id: Digest32,
        retention_policy_digest: Digest32,
        retention_decision_digest: Digest32,
        retain_until: UnixMillis,
    } = 2,
    CommittedClaimDestroyedByPolicy {
        claim_commitment_digest: Digest32,
        vault_segment_internal_id: Digest32,
        retention_policy_digest: Digest32,
        retention_decision_digest: Digest32,
        vault_destruction_receipt_digest: Digest32,
    } = 3,
}

struct RestartInvalidatedRecordV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    durable_task_id: DurableTaskIdV2,
    prior_input_state: RestartInvalidatedPriorInputStateV2,
    disposition: RestartInvalidatedDispositionV2,
    terminal_transaction_digest: Digest32,
    invalidated_at: UnixMillis,
    record_digest: Digest32,
}

struct AgentClaimMaterialIndexV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    durable_task_id: DurableTaskIdV2,
    input_state: InputPublicStateV2,
    pending_binding_digest: Option<Digest32>,
    pending_binding_tombstone_digest: Option<Digest32>,
    claim_commitment_digest: Option<Digest32>,
    restart_invalidated_record_digest: Option<Digest32>,
    record_digest: Digest32,
}

enum AgentAuthenticationRecoveryPhaseV2 {
    Prepared = 1,
    AuthenticatedAwaitingClaim = 2,
    Claimed = 3,
    RestartInvalidated = 4,
}

enum AgentAuthenticationAuthorizationStateV2 {
    NotCreated = 1,
    LiveAwaitingClaim {
        authorization_handle_hash: Digest32,
    } = 2,
    ConsumedByClaim {
        authorization_handle_hash: Digest32,
        claim_transaction_digest: Digest32,
    } = 3,
    TombstonedOnRestart {
        authorization_handle_hash: Digest32,
        tombstone_digest: Digest32,
    } = 4,
}

struct AgentAuthenticationRecoveryRecordV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    attempt_manifest_digest: Digest32,
    attempt_deployment_generation: u64,
    agent_claim_compatibility_edge_identity_digest: Option<Digest32>,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    authenticated_principal: PrincipalIdV2,
    claim_commitment_digest: Digest32,
    signed_correlation_digest: Digest32,
    agentd_identity: ServiceIdentityV2,
    auth_attempt_nonce: Nonce32,
    authentication_preparation_hash: Digest32,
    authentication_envelope_digest: Digest32,
    authorization_state: AgentAuthenticationAuthorizationStateV2,
    phase: AgentAuthenticationRecoveryPhaseV2,
    created_at: UnixMillis,
    expires_at: UnixMillis,
    record_digest: Digest32,
}

enum AgentAuthenticationInitialTransferTerminalStateV2 {
    NeverRedeemedTerminal = 1,
    ConsumedIntoTerminalizedCeremony = 2,
    Indeterminate = 3,
}

enum AgentAuthenticationSettlementTerminalStateV2 {
    NotCreated = 1,
    StoredNeverExportedInvalidated = 2,
    ExportedOrTransferRedeemed = 3,
    Indeterminate = 4,
}

enum AgentAuthenticationSettlementTransferTerminalStateV2 {
    NotCreated = 1,
    TerminalUnredeemed = 2,
    Redeemed = 3,
    Indeterminate = 4,
}

struct AgentAuthenticationTransferTerminalStateV2 {
    initial_transfer_record_digest: Digest32,
    initial_transfer_state:
        AgentAuthenticationInitialTransferTerminalStateV2,
    ceremony_record_digest: Option<Digest32>,
    settlement_record_digest: Option<Digest32>,
    settlement_state:
        AgentAuthenticationSettlementTerminalStateV2,
    settlement_transfer_record_digest: Option<Digest32>,
    settlement_transfer_state:
        AgentAuthenticationSettlementTransferTerminalStateV2,
}

struct UnsignedAgentAuthenticationClosureDescriptorV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    attempt_manifest_digest: Digest32,
    attempt_deployment_generation: u64,
    closure_issuing_manifest_digest: Digest32,
    closure_issuing_deployment_generation: u64,
    agent_claim_compatibility_edge_identity_digest: Option<Digest32>,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    signed_correlation_digest: Digest32,
    claim_commitment_digest: Digest32,
    authenticated_principal: PrincipalIdV2,
    agentd_identity: ServiceIdentityV2,
    originating_agentd_boot_id: BootIdV2,
    kerneld_identity: ServiceIdentityV2,
    originating_kerneld_boot_id: BootIdV2,
    approvald_identity: ServiceIdentityV2,
    auth_attempt_nonce: Nonce32,
    authentication_recovery_record_digest: Digest32,
    authentication_preparation_hash: Digest32,
    authentication_envelope_digest: Digest32,
    closure_nonce: Nonce32,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}

enum AgentAuthenticationClosureEvidenceV2 {
    NeverRegisteredDenylisted {
        complete_index_generation: u64,
        current_journal_head_digest: Digest32,
        denylist_tombstone_sequence: u64,
        denylist_tombstone_digest: Digest32,
        approvald_key_epoch: u64,
    } = 1,
    RegisteredInvalidatedUnredeemed {
        approval_record_digest: Digest32,
        ceremony_record_digest: Digest32,
        transfer_state: AgentAuthenticationTransferTerminalStateV2,
        approvald_terminal_transaction_digest: Digest32,
        complete_index_generation: u64,
        current_journal_head_digest: Digest32,
        denylist_tombstone_sequence: u64,
        denylist_tombstone_digest: Digest32,
        approvald_key_epoch: u64,
    } = 2,
    SettlementOrTransferObserved {
        approval_record_digest: Digest32,
        ceremony_record_digest: Digest32,
        transfer_state: AgentAuthenticationTransferTerminalStateV2,
        settlement_digest: Digest32,
        complete_index_generation: u64,
        current_journal_head_digest: Digest32,
        approvald_key_epoch: u64,
    } = 3,
    Indeterminate {
        observation_digest: Digest32,
        complete_index_generation: u64,
        current_journal_head_digest: Digest32,
        approvald_key_epoch: u64,
    } = 4,
}

struct UnsignedAgentAuthenticationAttemptClosureProofV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    attempt_manifest_digest: Digest32,
    attempt_deployment_generation: u64,
    closure_issuing_manifest_digest: Digest32,
    closure_issuing_deployment_generation: u64,
    agent_claim_compatibility_edge_identity_digest: Option<Digest32>,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    signed_correlation_digest: Digest32,
    claim_commitment_digest: Digest32,
    authenticated_principal: PrincipalIdV2,
    agentd_identity: ServiceIdentityV2,
    originating_agentd_boot_id: BootIdV2,
    kerneld_identity: ServiceIdentityV2,
    originating_kerneld_boot_id: BootIdV2,
    approvald_identity: ServiceIdentityV2,
    approvald_boot_id: BootIdV2,
    authentication_recovery_record_digest: Digest32,
    authentication_envelope_digest: Digest32,
    auth_attempt_nonce: Nonce32,
    closure_descriptor_digest: Digest32,
    evidence: AgentAuthenticationClosureEvidenceV2,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}

enum IngressSubjectV2 {
    NewRun {
        task: DurableTaskIdV2,
        authenticated_principal: PrincipalIdV2,
        ui_authentication_settlement_digest: Digest32,
        ingress_grant_digest: Digest32,
        task_context_digest: Digest32,
        kernel_run_nonce: Nonce32,
        expected_ingressd_identity: ServiceIdentityV2,
    } = 1,
    ExistingRun {
        durable_task_id: DurableTaskIdV2,
        durable_run_id: DurableRunIdV2,
        captured_run_revision_digest: RunRevisionDigestV2,
        expected_principal: PrincipalIdV2,
        ui_authentication_settlement_digest: Digest32,
        ingress_grant_digest: Digest32,
    } = 2,
}
```

`SignedAgentAuthenticationClosureDescriptorV2` is section 3.1's signed object
under the active kerneld task-correlation key with the distinct input:

```text
"SAVANA_AGENT_AUTH_CLOSURE_DESCRIPTOR_V2\0" ||
SHA-256(payload_bstr)
```

The exact non-signature record digests are:

```text
AgentAuthenticationRecoveryRecordDigest =
  SHA-256("SAVANA_AGENT_AUTH_RECOVERY_RECORD_V2\0" ||
          canonical_cbor(AgentAuthenticationRecoveryRecordV2
                         excluding record_digest))

AgentAuthenticationClosureDescriptorDigest =
  SHA-256("SAVANA_AGENT_AUTH_CLOSURE_DESCRIPTOR_DIGEST_V2\0" ||
          canonical_cbor(SignedAgentAuthenticationClosureDescriptorV2))
```

It contains no input, view, settlement, transfer token, preparation token, or
claim authority. Approvald accepts it only on AgentApproval operation 24 from
the exact bound agentd.

The descriptor and closure proof use a closed manifest matrix. If
`attempt_manifest_digest == closure_issuing_manifest_digest` and the two
deployment generations are equal,
`agent_claim_compatibility_edge_identity_digest` must be `None`. If either
differs, the field must be `Some` and must equal the one named, directional
`AgentClaimCompatibilityV2.edge_identity_digest` in the verified
closure-issuing manifest; that edge must authorize the exact claim/recovery
ABI and old-store read. Same-manifest `Some`, cross-manifest `None`, reverse,
transitive, wildcard, or an edge from any other manifest is noncanonical.
The closure proof repeats these five fields byte-for-byte from the descriptor.
Its approvald signer/key epoch is accepted only under the closure-issuing
manifest.

`SignedAgentAuthenticationAttemptClosureProofV2` is section 3.1's signed
object for the unsigned payload under the existing approvald
UI-authentication settlement key, but with the distinct signature input
`"SAVANA_AGENT_AUTH_ATTEMPT_CLOSURE_PROOF_V2\0" ||
SHA-256(payload_bstr)`. It introduces no fifth settlement key or key family
and cannot be decoded as a UI-authentication settlement. Kerneld accepts only
evidence tags `NeverRegisteredDenylisted` and
`RegisteredInvalidatedUnredeemed` for replacement.
`SettlementOrTransferObserved`,
`Indeterminate`, a missing row/tombstone, an unverifiable complete index or
journal head, or an expired/wrong-attempt proof requires
`RestartInvalidated`.

```text
AgentAuthenticationTransferTerminalStateDigest =
  SHA-256("SAVANA_AGENT_AUTH_TRANSFER_TERMINAL_STATE_V2\0" ||
          canonical_cbor(AgentAuthenticationTransferTerminalStateV2))
```

The closure evidence matrix is canonical:

| Evidence tag | Required proof |
|---|---|
| `NeverRegisteredDenylisted` | a complete approval index proves no record for the descriptor; the same transaction writes a permanent envelope/attempt denylist tombstone and advances the authenticated journal head |
| `RegisteredInvalidatedUnredeemed` | the exact registered record is terminalized; the fixed descendant-state matrix below proves no settlement was exported and no settlement transfer was redeemed; the same transaction writes the denylist tombstone |
| `SettlementOrTransferObserved` | a stored settlement was exported, a settlement transfer was redeemed, or another settlement-bearing descendant was observed; all exact descendant digests and the observed settlement digest are bound |
| `Indeterminate` | approvald cannot prove a complete safe or redeemed disposition; only authenticated index generation, journal head, key epoch, and observation digest are signed |

Registration operation 22 checks the permanent denylist before record lookup
and rejects a later presentation of a tombstoned old envelope. The fixed
transfer struct represents exactly one initial transfer, at most one
ceremony, at most one settlement, and at most one settlement transfer for the
exact attempt; there is no opaque availability bit or descendant-set digest.
For `RegisteredInvalidatedUnredeemed`, the only canonical safe rows are:

| Initial transfer | Ceremony | Settlement | Settlement transfer |
|---|---:|---|---|
| `NeverRedeemedTerminal` | `None` | `None/NotCreated` | `None/NotCreated` |
| `ConsumedIntoTerminalizedCeremony` | `Some`, exact terminalized ceremony | `None/NotCreated` | `None/NotCreated` |
| `ConsumedIntoTerminalizedCeremony` | `Some`, exact terminalized ceremony | `Some/StoredNeverExportedInvalidated` | `None/NotCreated` or `Some/TerminalUnredeemed` |

`ExportedOrTransferRedeemed`, a redeemed settlement transfer,
`Indeterminate`, or any other option/state combination is never safe
replacement evidence. Any omitted/extra record, wrong attempt, duplicate,
reordered substitute, stale complete-index generation, wrong authenticated
journal head, or unaccounted settlement-bearing descendant prevents a safe
proof.

When approvald reads an attempt record written under an older manifest, the
closure-issuing destination manifest must also contain the exact
`PersistentStoreCompatibilityV2` entries for approvald's authentication
record, ceremony, settlement, transfer, denylist, replay, and journal stores.
Each desired reader range must contain the creating schema epoch and each
migration digest, post-migration digest rule, and validator artifact must
verify. Those complete store declarations are required in addition to
`AgentClaimCompatibilityV2`; protocol-ABI equality does not imply store
readability. Without the exact claim edge and all store declarations approvald may emit only
`Indeterminate`, and kerneld advances to `RestartInvalidated`.

`AgentClaimCompatibilityV2` is the exact deployment-defined immutable
manifest component, not a protocol-local signed object. Kerneld verifies its
component identity and `edge_identity_digest` through the active signed
destination manifest. The component is named and directional for one exact
old/new manifest pair; it fixes identical protocol/claim ABI, exact
agentd/kerneld logical identities, from/to persistent-store schemas and
compatibility, the complete retained vault-key read set, and the complete
agent-view projection identity/digest set. Compatibility is denied by
default; reverse, transitive, wildcard, caller-supplied, same-schema-inferred,
omitted-key/projection, or component-authorization-free edges do not exist.

`non_authorizing_record_nonce` provides only record uniqueness and audit
correlation. It has no resolver, is never returned, and no operation accepts
it. The claim commitment's expected agentd, initial stable value/document,
vault segment, active tool set, principal, run revision, and settlement must
all equal the committed task before any authentication preparation is minted.

The new-run principal is selected only by the completed
`IngressInput` UI-authentication settlement before kerneld issues
`IngressUiAuthorizationHandleV2` or accepts any input byte. It is stored in
the pending durable task and copied into `IngressSubjectV2`; the later ingress
approval cannot select or replace it. In the same operation-47 transaction,
kerneld creates exactly one non-capability
`PendingAgentClaimBindingV2`. That pre-input binding contains no run, value,
document, vault, tool-set, or claim-authorization field and is never accepted
as a resolver.

```text
PendingAgentClaimBindingDigest =
  SHA-256("SAVANA_PENDING_AGENT_CLAIM_BINDING_V2\0" ||
          canonical_cbor(PendingAgentClaimBindingV2))

PendingAgentClaimBindingTombstoneDigest =
  SHA-256("SAVANA_PENDING_AGENT_CLAIM_BINDING_TOMBSTONE_V2\0" ||
          canonical_cbor(PendingAgentClaimBindingTombstoneV2))

RestartInvalidatedRecordDigest =
  SHA-256("SAVANA_RESTART_INVALIDATED_RECORD_V2\0" ||
          canonical_cbor(RestartInvalidatedRecordV2
                         excluding record_digest))

AgentClaimMaterialIndexRecordDigest =
  SHA-256("SAVANA_AGENT_CLAIM_MATERIAL_INDEX_V2\0" ||
          canonical_cbor(AgentClaimMaterialIndexV2
                         excluding record_digest))
```

`PendingAgentClaimBindingTombstoneV2` has an exact option rule:
`ConsumedIntoClaimCommitment` requires
`derived_claim_commitment_digest=Some` and every other reason requires
`None`. The authoritative claim-material index has the following complete
matrix:

| Main input state | live pending binding | binding tombstone | claim commitment | restart record |
|---|---:|---:|---:|---:|
| `Granted`, `Receiving`, `Finalizing`, `AwaitingApproval`, `Committing` | `Some` | `None` | `None` | `None` |
| `CommittedUnclaimed`, `AgentAuthPending` | `None` | `Some(ConsumedIntoClaimCommitment)` | `Some` | `None` |
| `AgentClaimed` | `None` | `Some(ConsumedIntoClaimCommitment)` | `Some`, retained as redeemed evidence | `None` |
| `Denied`, `Aborted`, `Expired`, `FailedClosed` | `None` | `Some` with the matching terminal reason | `None` | `None` |
| precommit `RestartInvalidated` | `None` | `Some(RestartInvalidated)` | `None` | `Some(PreCommitStagingCleared)` |
| committed `RestartInvalidated` | `None` | `Some(ConsumedIntoClaimCommitment)` | `Some` | `Some(CommittedClaimRetainedByPolicy or CommittedClaimDestroyedByPolicy)` |

Every omitted, extra, cross-reason, or digest-mismatched option is durable
corruption and fails stop. `PreCommitStagingCleared` is legal only from
`Granted`, `Receiving`, `Finalizing`, `AwaitingApproval`, or `Committing`;
its typed payload cannot name a run, committed claim, committed vault
segment, retention decision, or destruction receipt. The two committed
dispositions are legal only from `CommittedUnclaimed` or
`AgentAuthPending`. Each binds the exact stored claim commitment, exact vault
segment, signed retention-policy digest, and exact retention-decision digest;
the retained branch also fixes the retention deadline and the destroyed
branch fixes the durable destruction receipt. `AgentClaimed` has no
`RestartInvalidated` edge.

Operation 47 exact replay must find the same pending-binding digest in the
same atomic UI-authorization replay record; it neither creates a second
binding nor converts the binding into a commitment. A changed principal,
settlement, expected agentd, manifest, expiry, or request conflicts before
mutation. On approved operation 43 input commit, one transaction permanently
consumes and tombstones the exact pending binding, creates the sole
`UnredeemableAgentClaimCommitmentV2` after the stable run/value/document/vault
and active-tool identities exist, and records that one derived commitment
digest in both the tombstone and index. Exact response-loss recovery observes
that committed index and never derives a second commitment. Denial, abort,
expiry, invalid settlement, precommit restart, or any precommit failure
clears zeroizing staging and tombstones the pending binding without creating
a run, vault, claim commitment, or committed-vault reference.

`PrepareFollowupIngress` is reachable only from an authenticated
`AgentTabSessionCapabilityV2` that resolves through the exact live
`AgentSessionHandleV2` and `RunHandleV2`; JARVIS has no route or DTO that can
trigger it. The request contains no revision field. While holding the run
lock, kerneld reads the canonical server-owned revision and snapshots its
immutable `RunRevisionDigestV2` into the UI-authentication binding,
`IngressSubjectV2::ExistingRun`, ingress approval envelope, and pending
settlement record. `CommitInputSettlement` compares that digest with the
current durable run revision and, only on equality, atomically appends the
input and advances the run revision in the same transaction. Any concurrent
revision change returns `StateConflict` with no input, approval, value, run
revision, or replay-state mutation.

```text
RunRevisionDigest =
  SHA-256("SAVANA_RUN_REVISION_V2\0" ||
          canonical_cbor(RunRevisionV2))

RunRevisionAdvanceDigest =
  SHA-256("SAVANA_RUN_REVISION_ADVANCE_V2\0" ||
          canonical_cbor([
            old_run_revision_digest,
            old_revision_number,
            new_revision_number,
            transition_kind_u16,
            transition_subject_digest
          ]))

CommittedInputSetDigest =
  SHA-256("SAVANA_COMMITTED_INPUT_SET_V2\0" ||
          canonical_cbor([
            item_count,
            BoundedSortedVec<CommittedInputSetItemV2, 4096>
          ]))

ValueProvenanceSetDigest =
  SHA-256("SAVANA_VALUE_PROVENANCE_SET_V2\0" ||
          canonical_cbor([
            item_count,
            BoundedSortedVec<ValueProvenanceSetItemV2, 65536>
          ]))

ActionStateSetDigest =
  SHA-256("SAVANA_ACTION_STATE_SET_V2\0" ||
          canonical_cbor([
            item_count,
            BoundedSortedVec<ActionStateSetItemV2, 4096>
          ]))

VaultStateSetDigest =
  SHA-256("SAVANA_VAULT_STATE_SET_V2\0" ||
          canonical_cbor([
            item_count,
            BoundedSortedVec<VaultStateSetItemV2, 65536>
          ]))

ActiveToolSetDigest =
  SHA-256("SAVANA_ACTIVE_TOOL_SET_V2\0" ||
          canonical_cbor([
            item_count,
            BoundedSortedVec<ActiveToolSetItemV2, 4096>
          ]))

InputValueProvenanceSetDigest =
  SHA-256("SAVANA_INPUT_VALUE_PROVENANCE_SET_V2\0" ||
          canonical_cbor([
            item_count,
            BoundedSortedVec<InputValueProvenanceSetItemV2, 65536>
          ]))
```

Committed inputs sort strictly by `input_ordinal`; value-provenance and
input-value-provenance items by `value_internal_id`; action states by
`action_intent_id`; vault states by `vault_segment_internal_id`; and active
tools by `(tool_descriptor_digest, tool_registry_ordinal)`. Every encoded
count equals the vector length. Duplicate sort keys, gaps in input ordinals,
an item from another run/task/manifest, a state tag inconsistent with the
referenced durable record, or any aggregate digest substituted for an item is
rejected. `RunRevisionV2` recomputes the first four sets from the complete
current durable run snapshot. The claim commitment recomputes its
input-value-provenance and active-tool sets from the exact approved input
transaction and active signed registry/policy snapshot; neither caller nor
recovery code supplies a set digest.

The field mapping is exact:
`committed_input_set_digest = CommittedInputSetDigest`,
`value_provenance_set_digest = ValueProvenanceSetDigest`,
`action_state_set_digest = ActionStateSetDigest`,
`vault_state_set_digest = VaultStateSetDigest`,
`input_value_provenance_set_digest = InputValueProvenanceSetDigest`, and
`active_tool_set_digest = ActiveToolSetDigest`.

Genesis uses revision number zero, `previous_revision_digest = None`,
`transition_kind = Genesis`, and a manifest-defined genesis subject digest.
Every later revision increments the number by exactly one, sets
`previous_revision_digest` to the stored old digest, and incorporates
the exact `RunRevisionAdvanceDigest` in `transition_advance_digest`;
`transition_subject_digest` remains the immutable digest of the concrete
input/plan/value/intent/result/vault/session transition. Genesis sets
`transition_advance_digest` to
`SHA-256("SAVANA_RUN_REVISION_GENESIS_V2\0" ||
transition_subject_digest)`. Under the single run lock, the kernel compares
the pending internally captured digest to the
stored digest, writes the semantic mutation, canonical next revision, durable
task/public status, claim-material index transition where applicable, and
replay record in
one transaction. There is no API that accepts a caller-selected
`RunRevisionV2`, revision number, previous digest, or expected revision
digest.

When ingress first reaches `CommittedUnclaimed`, the same transaction consumes
the exact previously persisted `PendingAgentClaimBindingV2` and writes the
only `UnredeemableAgentClaimCommitmentV2` and its digest
`SHA-256("SAVANA_UNREDEEMABLE_AGENT_CLAIM_V2\0" ||
canonical_cbor(commitment))`. Possession of that digest or the signed task
correlation grants nothing. A cross-manifest resume is permitted only when
the destination signed manifest contains the exact named, directional
deployment `AgentClaimCompatibilityV2` component and its
`edge_identity_digest`; absence,
reverse use, transitive inference, protocol-ABI mismatch, or any mismatched
field fails closed.

The pending-binding record, its terminal tombstone, the unique commitment,
the claim-material index, and any restart-disposition record form one
retention DAG. A live pending binding is never GC'd before its input terminal
transaction. A consumed/tombstoned binding and the unique commitment remain
until the task query tombstone, every agent-authentication closure proof,
every vault retention/destruction proof, and every descendant run/session
reference have expired. GC cannot turn an observed binding nonce, settlement,
or commitment digest back into absence, and replay/recovery may read but
never recreate any collected authority.

The settlement binds envelope digest, decision, authenticated principal,
authentication-context digest, credential digest, UP=true, UV=true,
issue/expiry, challenge nonce, settlement nonce, approvald key, and signature.

```text
IngressSubjectDigest =
  SHA-256("SAVANA_INGRESS_SUBJECT_V2\0" ||
          canonical_cbor(IngressSubjectV2))
```

Every ingress approval envelope sets `expected_principal` to this pre-input
principal. The approval-display UI-authentication principal and the later
approval settlement principal must both equal it. On approve, kerneld creates
the run with the same binding. A signed deny is authenticated and
replay-protected but grants no authority.

### 9.2 File/OCR provenance

```rust
enum InputSourceKindV2 {
    Chat = 1,
    Paste = 2,
    FileUpload = 3,
}

enum InputSourceProvenanceV2 {
    Direct {
        source_kind: InputSourceKindV2,
        original_byte_length: u64,
        original_sha256: Digest32,
        normalization_version: VersionV2,
    },
    ParsedDocument {
        source_kind: InputSourceKindV2,
        original_byte_length: u64,
        original_sha256: Digest32,
        declared_media_type: ClosedMediaTypeV2,
        detected_media_type: ClosedMediaTypeV2,
        extension_class: ClosedExtensionClassV2,
        parser_implementation_id: ImplementationIdV2,
        parser_semantic_version: VersionV2,
        parser_code_digest: Digest32,
        renderer_code_digest: Option<Digest32>,
        ocr_model_set_digest: Option<Digest32>,
        normalization_version: VersionV2,
        page_records: BoundedVec<PageProvenanceV2, 2048>,
        extracted_output_digest: Digest32,
    },
}

struct PageProvenanceV2 {
    page_index: u32,
    extracted_channel_first_sequence: u32,
    extracted_channel_chunk_count: u32,
    rendered_byte_length: u64,
    rendered_input_digest: Digest32,
    extracted_byte_length: u64,
    extracted_text_digest: Digest32,
    character_count: u32,
    confidence_class: ClosedConfidenceClassV2,
}

struct UnsignedParserWorkerJobDescriptorV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    ingressd_identity: ServiceIdentityV2,
    job_nonce: Nonce32,
    parser_job_session_binding_digest: Digest32,
    original_byte_length: u64,
    original_sha256: Digest32,
    declared_media_type: ClosedMediaTypeV2,
    detected_media_type: ClosedMediaTypeV2,
    worker_artifact_digest: Digest32,
    parser_implementation_id: ImplementationIdV2,
    parser_code_digest: Digest32,
    renderer_code_digest: Option<Digest32>,
    ocr_model_set_digest: Option<Digest32>,
    normalization_version: VersionV2,
    output_limits_digest: Digest32,
    ephemeral_result_public_key: FixedBytesV2<32>,
    ephemeral_result_key_id: Ed25519KeyIdV2,
    expires_at: UnixMillis,
}

struct ParserWorkerPageFrameV2 {
    job_nonce: Nonce32,
    page_index: u32,
    page_chunk_index: u32,
    final_chunk_for_page: bool,
    rendered_input_digest: Digest32,
    extracted_chunk: ZeroizingBytesV2,
    extracted_chunk_digest: Digest32,
    transcript_step_digest: Digest32,
}

struct UnsignedParserWorkerResultAttestationV2 {
    schema_version: u16,                 // exactly 2
    job_nonce: Nonce32,
    job_descriptor_digest: Digest32,
    parser_job_session_binding_digest: Digest32,
    worker_artifact_digest: Digest32,
    ephemeral_result_key_id: Ed25519KeyIdV2,
    original_byte_length: u64,
    original_sha256: Digest32,
    page_count: u32,
    page_records: BoundedVec<PageProvenanceV2, 2048>,
    ordered_page_frame_transcript_digest: Digest32,
    extracted_byte_length: u64,
    extracted_output_digest: Digest32,
    completed_at: UnixMillis,
}

enum ParserWorkerPipeFrameV2 {
    Job {
        descriptor: SignedParserWorkerJobDescriptorV2,
        original: ZeroizingBytesV2,
    } = 1,
    Page(ParserWorkerPageFrameV2) = 2,
    Complete {
        attestation: SignedParserWorkerResultAttestationV2,
    } = 3,
    Failed {
        class: PublicFailureClassV2,
    } = 4,
}
```

```text
InputChannelCommitmentsDigest =
  SHA-256("SAVANA_INPUT_CHANNEL_COMMITMENTS_V2\0" ||
          canonical_cbor(strictly_sorted_InputChannelCommitmentV2_array))

InputSourceProvenanceDigest =
  SHA-256("SAVANA_INPUT_SOURCE_PROVENANCE_V2\0" ||
          canonical_cbor(InputSourceProvenanceV2))

ParserWorkerJobDescriptorDigest =
  SHA-256("SAVANA_PARSER_WORKER_JOB_DESCRIPTOR_V2\0" ||
          exact_unsigned_job_descriptor_payload_bstr)

ParserWorkerJobDescriptorSignature =
  Ed25519.sign(ingressd_parser_job_descriptor_key,
               "SAVANA_PARSER_WORKER_JOB_DESCRIPTOR_SIGNATURE_V2\0" ||
               SHA-256(exact_unsigned_job_descriptor_payload_bstr))

ParserWorkerPageTranscriptStep[0] =
  SHA-256("SAVANA_PARSER_WORKER_TRANSCRIPT_BEGIN_V2\0" ||
          job_nonce || ParserWorkerJobDescriptorDigest)

ParserWorkerPageTranscriptStep[n + 1] =
  SHA-256("SAVANA_PARSER_WORKER_TRANSCRIPT_STEP_V2\0" ||
          ParserWorkerPageTranscriptStep[n] ||
          canonical_cbor(ParserWorkerPageFrameV2[n] excluding
                         transcript_step_digest))
```

These are the exact `channel_commitments_digest` and
`source_provenance_digest` placed in `ApprovalBindingV2::Ingress`; neither
contains a capability handle.

The raw filename is original data and is tokenized or discarded. kerneld
verifies worker/model identities against the active manifest. Root provenance
and the approval envelope bind original file digest, parser/OCR identity, page
order, extraction digest, and normalization identity.

Page indexes MUST be contiguous from zero and page records strictly increasing.
Each page owns one non-overlapping contiguous range of `ExtractedPage` chunk
sequences; concatenating those ranges in page order must consume that channel
exactly once. kerneld recomputes rendered and extracted lengths/digests and
requires the final concatenated extraction digest to equal both the
`ExtractedPage` channel commitment and `extracted_output_digest`. Empty hidden
pages, overlapping/gapped sequence ranges, worker-supplied digest mismatch,
page-count mismatch, or output outside the page/scalar/pixel ceilings fails
closed before approval.

The parser/OCR ABI is a private one-job inherited pipe, not a socket, public
operation, browser route, or reusable worker service. The signed descriptor is
the first and only `Job` frame; exactly one terminal `Complete` or `Failed`
frame follows a bounded sequence of page frames. Ingressd's
deployment-pinned one-shot launcher creates one fresh Ed25519 result keypair
for the job, places its
public key and key ID in the ingressd-signed descriptor, injects only the
non-exportable or locked-memory private signing handle into the exact
manifest-measured worker artifact, and destroys it when that worker exits.
The worker has no persistent service, handshake, approval, deployment, or
replay key.

The descriptor signer must equal
`ServiceIdentityLockProtocolPayloadV2.parser_worker_job_descriptor_key_id`;
no general ingress handshake, replay, approval, deployment, or worker key may
sign that domain. The job nonce, ephemeral result key ID, input session,
original digest, measured worker artifact, parser/renderer/OCR identities,
output limits, and expiry are checked before the worker receives source bytes.
Every `ocr_model_set_digest=Some` equals the complete model-set digest of the
one active signed OCR-model manifest component, including its component-fixed
canonical item schema, count, domain, sort key, and duplicate rule.
`None` is canonical only when both the pinned parser route and detected media
type require no OCR; a local subset, discovered model list, or partial digest
is forbidden.

`SignedParserWorkerResultAttestationV2` is signed by that exact ephemeral key
over
`"SAVANA_PARSER_WORKER_RESULT_SIGNATURE_V2\0" ||
SHA-256(payload_bstr)`. It binds the signed descriptor, worker artifact,
original input, ordered page/frame transcript, every page record, and final
output digest. Ingressd verifies the inherited pipe identity, descriptor
signature, ephemeral key ID, exact worker process/artifact, nonce, frame
order, bounds, all incremental digests, and the final signature before asking
kerneld to commit any `ExtractedPage` channel. Kerneld keeps worker output in
uncommitted staging until the same checks and provenance equality pass.

IngressKernel operation 48 verifies the descriptor signature, installation,
manifest/generation, exact ingressd identity, expiry, worker/model/limit
identities, and the `parser_job_session_binding_digest` returned for that
same input session. It reserves the job nonce and returns one typed
`ParserExtractionHandleV2`; it does not create an extracted channel.
Operation 49 accepts only the next exact page/chunk frame for that handle,
recomputes the transcript step, and stores its bytes in zeroizing
uncommitted parser staging. Operation 50 verifies the job's exact ephemeral
signer, descriptor and binding digests, complete contiguous transcript,
page records, lengths, limits, original source digest, and final output
digest. Only its atomic success converts the staged frames into the one
`InputChannelV2::ExtractedPage` commitment and stores the exact parsed-source
provenance digest used by `FinalizeInput`. An exact operation-48/49 replay
returns the existing typed handle/acknowledgement; operation 50 is one-way
and its durable input status is the recovery projection. No generic append or
finalize decoder accepts a descriptor, frame, attestation, or extracted
channel.

A browser append can contribute only the server-selected `ChatText` or
`OriginalSource` channel. Browser bytes, an ingressd request without the
complete worker attestation, a reused job nonce/key, a frame from another
worker/job, reordered/duplicated page or chunk, or an attestation over another
input/output is rejected and clears the uncommitted extraction. No browser
field is interpreted as `ExtractedPage`.

When policy requires later delivery of the original file, it becomes an
immutable bounded vault blob. Otherwise source bytes are cleared after the
binding commits. Worker temporary storage is memory-backed or per-job
encrypted with an in-memory ephemeral key; plaintext disk temporary files are
forbidden.

## 10. Mutation replay and response loss

There are three disjoint client replay-key ABIs:

```rust
struct BootReplayKeyV2 {
    server_boot_id: BootIdV2,
    endpoint_role: ReplayEndpointRoleV2,
    client_identity: ReplayClientIdentityV2,
    client_boot_id: Option<BootIdV2>,
    peer_identity: PeerIdentityBindingV2,
    request_id: RequestIdV2,
}

enum BrowserMutationRouteV2 {
    JarvisBootstrapContinue = 1,
    IngressBootstrapAccept = 2,
    UiAuthenticationAccept = 3,
    UiAuthenticationBegin = 4,
    UiAuthenticationFinish = 5,
    IngressUiAuthenticationComplete = 6,
    AgentUiAuthenticationComplete = 7,
    ApprovalDecisionBegin = 8,
    ApprovalDecisionFinish = 9,
    EnrollmentBegin = 10,
    EnrollmentFinish = 11,
    IngressInput = 12,
    AgentReadView = 13,
    AgentAction = 14,
}

enum BrowserReplayBindingV2 {
    Tab {
        tab_identity_digest: Digest32,
    } = 1,
    TypedOneWayCapability {
        capability_type_tag: u16,
        resolver_typed_hash: Digest32,
    } = 2,
    BootstrapSelector {
        selector_typed_hash: Digest32,
    } = 3,
}

struct BrowserMutationReplayKeyV2 {
    server_boot_id: BootIdV2,
    endpoint_role: ReplayEndpointRoleV2,
    source_origin: FixedOriginV2,
    route: BrowserMutationRouteV2,
    binding: BrowserReplayBindingV2,
    client_request_nonce: Option<Nonce32>,
}

struct DurablePrepareIngressKeyV2 {
    protocol_major: u16,                 // exactly 2
    installation_id: Digest32,
    jarvis_principal: JarvisPrincipalIdV2,
    jarvis_os_peer_class: JarvisOsPeerClassV2,
    client_request_nonce: Nonce32,
}

enum ActionStateEmissionKindV2 {
    ProposedPending = 1,
    EvaluatingPending = 2,
    AwaitingApprovalPending = 3,
    AuthorizedExecutionTicket = 4,
    DispatchedExecution = 5,
    TerminalExecution = 6,
}

struct ActionStateEmissionKeyV2 {
    installation_id: Digest32,
    action_intent_id: ActionIntentIdV2,
    intent_projection_version: u64,
    emission_kind: ActionStateEmissionKindV2,
}

struct ActionIntentEmissionKeyV2 {
    installation_id: Digest32,
    action_intent_id: ActionIntentIdV2,
    authenticated_agentd_identity: ServiceIdentityV2,
    authenticated_agentd_client_boot_id: BootIdV2,
    kerneld_server_boot_id: BootIdV2,
    creating_manifest_digest: Digest32,
    creating_deployment_generation: u64,
}

struct ExecutionDocumentEmissionKeyV2 {
    installation_id: Digest32,
    execution_internal_id: Digest32,
    execution_status_revision: u64,
    outcome_commit_digest: Digest32,
}

enum ReplayLookupKeyV2 {
    Boot(BootReplayKeyV2) = 1,
    DurablePrepareIngress(DurablePrepareIngressKeyV2) = 2,
    BrowserMutation(BrowserMutationReplayKeyV2) = 3,
}

enum InternalEmissionKeyV2 {
    ActionState(ActionStateEmissionKeyV2) = 1,
    ExecutionDocument(ExecutionDocumentEmissionKeyV2) = 2,
    ActionIntent(ActionIntentEmissionKeyV2) = 3,
}

enum ReplayEndpointRoleV2 {
    JarvisAgentControl = 1,
    AgentKernel = 2,
    IngressKernel = 3,
    KernelExecutor = 4,
    AgentApproval = 5,
    IngressApproval = 6,
    ApprovalAdmin = 7,
    IngressBrowser = 8,
    AgentBrowser = 9,
    ApprovalBrowser = 10,
    JarvisBrowser = 11,
}

enum ReplayClientIdentityV2 {
    Daemon {
        service_identity: ServiceIdentityV2,
    } = 1,
    Jarvis {
        principal: JarvisPrincipalIdV2,
        os_peer_class: JarvisOsPeerClassV2,
    } = 2,
    Browser {
        origin: FixedOriginV2,
        browser_replay_binding_digest: Digest32,
    } = 3,
}
```

`BrowserMutationReplayKeyV2` is the only replay key for loopback HTTP
mutations; HTTP never invents a transport `RequestIdV2`. The route/binding/
nonce matrix is closed:

| Route | Required source/role | Binding | nonce |
|---|---|---|---|
| `JarvisBootstrapContinue` | 8765 / `JarvisBrowser` | exact selector typed hash | `Some` |
| `IngressBootstrapAccept` | 8765 tag 1 or 8768 tag 7 / `IngressBrowser` | exact kernel-transfer typed hash | `None` |
| `UiAuthenticationAccept` | carrier table's exact source / `ApprovalBrowser` | exact purpose-specific transfer typed hash | `None` |
| `UiAuthenticationBegin` | 8766 / `ApprovalBrowser` | exact purpose-specific pre-auth typed hash | `Some` |
| `UiAuthenticationFinish` | 8766 / `ApprovalBrowser` | exact purpose-specific ceremony typed hash | `Some` |
| `IngressUiAuthenticationComplete` | 8766 / `IngressBrowser` | exact ingress settlement-transfer typed hash | `None` |
| `AgentUiAuthenticationComplete` | 8766 / `AgentBrowser` | exact agent settlement-transfer typed hash | `None` |
| `ApprovalDecisionBegin` | 8766 / `ApprovalBrowser` | exact approval-tab digest | `Some` |
| `ApprovalDecisionFinish` | 8766 / `ApprovalBrowser` | exact decision-ceremony typed hash | `Some` |
| `EnrollmentBegin` | 8766 / `ApprovalBrowser` | exact enrollment-handle typed hash | `Some` |
| `EnrollmentFinish` | 8766 / `ApprovalBrowser` | exact enrollment-ceremony typed hash | `Some` |
| `IngressInput` | 8767 / `IngressBrowser` | exact ingress-tab digest | `Some` |
| `AgentReadView`, `AgentAction` | 8768 / `AgentBrowser` | exact agent-tab digest | `Some` |

`TypedOneWayCapability` with `client_request_nonce=None` is legal only for the
four fixed form-consumption routes shown. Its first transaction consumes the
resolver and atomically writes a durable typed consumption tombstone,
request digest, response commitment, and capability-aware replay capsule.
An exact same-origin resubmission resolves that tombstone and returns the
same response only after every emitted resolver commitment verifies; changed
form bytes, origin, route, or capability type conflicts. `Tab` and
`BootstrapSelector` require `Some(client_request_nonce)` and reject `None`.
All other route/binding/nonce/source combinations fail before lookup.
Approval display and static/bootstrap GETs are queries and allocate no replay
row.

`server_boot_id` is a fresh random 32-byte identifier for one service process
start, not the OS boot ID. Every ordinary mutation uses
`BootReplayKeyV2` on authenticated local transports or
`BrowserMutationReplayKeyV2` on loopback HTTP; a later server boot cannot
look either up or open its boot-scoped capsule.
Only JarvisAgentControl tag 10 additionally creates the distinct durable
semantic key. The durable key contains no server boot or request ID, so the
same authenticated principal/OS-peer/nonce identifies one task across agentd
boots. The original exact request digest and signed task-correlation digest
are fixed in that durable row. Reusing the durable key with different request
bytes returns `IdempotencyConflict` and never creates another task.

```rust
enum ReplayCapsuleScopeV2 {
    BootScoped {
        server_boot_id: BootIdV2,
    } = 1,
    DurablePrepareIngress {
        durable_key_digest: Digest32,
        query_tombstone_retain_until: UnixMillis,
    } = 2,
}

enum ReplayCapsuleKindV2 {
    ExactResponseSnapshot = 1,
    TypedCapabilityResponseEmission = 2,
    ActionIntentHandleEmission = 3,
    ActionStateHandleEmission = 4,
    DurableTaskHandleEmission = 5,
    ExecutionDocumentHandleEmission = 6,
    ActionIntentEmissionReference = 7,
}

struct CapabilityResolverCommitmentV2 {
    response_field_ordinal: u16,
    capability_type_tag: u16,
    token_digest: Digest32,
    resolver_typed_hash: Digest32,
}

struct BrowserObjectRefResolverCommitmentV2 {
    response_field_ordinal: u16,
    agent_ref_type_tag: u16,
    reference_digest: Digest32,
    agentd_object_record_id: AgentdObjectRecordIdV2,
    reference_binding_revision: u64,
    resolver_typed_hash: Digest32,
}

enum ReplayCapsuleMaterialV2 {
    ExactResponseSnapshot {
        response_schema_digest: Digest32,
        canonical_response_bytes: ZeroizingBytesV2,
        exact_response_digest: Digest32,
    } = 1,
    TypedCapabilityResponseEmission {
        operation_tag: u16,
        response_schema_digest: Digest32,
        canonical_response_bytes: ZeroizingBytesV2,
        resolver_commitments:
            BoundedSortedVec<CapabilityResolverCommitmentV2, 256>,
        browser_object_ref_commitments:
            BoundedSortedVec<BrowserObjectRefResolverCommitmentV2, 4096>,
    } = 2,
    ActionIntentHandleEmission {
        action_intent_id: ActionIntentIdV2,
        action_intent_handle: ZeroizingFixedBytesV2<32>,
        handle_resolver_typed_hash: Digest32,
        stable_material_digest: Digest32,
        projection_rule_digest: Digest32,
    } = 3,
    ActionStateHandleEmission {
        action_intent_id: ActionIntentIdV2,
        intent_projection_version: u64,
        child: ActionStateChildHandleEmissionV2,
        child_material_digest: Digest32,
    } = 4,
    DurableTaskHandleEmission {
        durable_task_id: DurableTaskIdV2,
        task_handle: ZeroizingFixedBytesV2<32>,
        task_handle_resolver_typed_hash: Digest32,
        signed_task_correlation_digest: Digest32,
        original_request_digest: Digest32,
        query_tombstone_retain_until: UnixMillis,
    } = 5,
    ExecutionDocumentHandleEmission {
        document_internal_digest: Digest32,
        document_handle: ZeroizingFixedBytesV2<32>,
        document_resolver_typed_hash: Digest32,
        outcome_commit_digest: Digest32,
    } = 6,
    ActionIntentEmissionReference {
        key: ActionIntentEmissionKeyV2,
        record_digest: Digest32,
        stable_proposal_digest: Digest32,
    } = 7,
}

enum ActionStateChildHandleEmissionV2 {
    Pending {
        handle: ZeroizingFixedBytesV2<32>,
        resolver_typed_hash: Digest32,
    } = 1,
    ExecutionTicket {
        handle: ZeroizingFixedBytesV2<32>,
        resolver_typed_hash: Digest32,
    } = 2,
    Execution {
        handle: ZeroizingFixedBytesV2<32>,
        resolver_typed_hash: Digest32,
    } = 3,
}

enum ReplayResponseCommitmentV2 {
    ExactBytes {
        response_digest: Digest32,
    } = 1,
    CanonicalProjection {
        stable_material_digest: Digest32,
        projection_rule_digest: Digest32,
        last_emitted_projection_version: u64,
        last_emitted_response_digest: Digest32,
    } = 2,
}

enum ReplaySlotStateV2 {
    Active = 1,
    Poisoned = 2,
    Expired = 3,
}

enum InternalEmissionRecordStateV2 {
    Active = 1,
    Poisoned = 2,
    Expired = 3,
}

enum ReplayCapsuleContextV2 {
    ClientReplay {
        lookup_key: ReplayLookupKeyV2,
        request_digest: Digest32,
        operation_tag: u16,
        operation_class: OperationClassV2,
        client_identity: ReplayClientIdentityV2,
        originating_client_boot_id: Option<BootIdV2>,
        authenticated_peer_identity: PeerIdentityBindingV2,
        bound_internal_object_id: Digest32,
    } = 1,
    InternalEmission {
        emission_key: InternalEmissionKeyV2,
        owner_internal_object_id: Digest32,
        owner_state_revision: u64,
        emission_material_digest: Digest32,
    } = 2,
}

enum ReplayCapsuleKeyBindingV2 {
    BootFresh {
        role: ReplayKeyRoleV2,
        server_boot_id: BootIdV2,
        fresh_key_id: ReplayAeadKeyIdV2,
        locked_memory_handle_identity_digest: Digest32,
    } = 1,
    AgentdDurableEscrow {
        agentd_durable_replay_aead_lock_digest: Digest32,
        key_epoch: u64,
        key_id: ReplayAeadKeyIdV2,
    } = 2,
}

struct ReplayCapsuleAadV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    issuer_service_identity: ServiceIdentityV2,
    context: ReplayCapsuleContextV2,
    response_schema_digest: Digest32,
    creating_manifest_digest: Digest32,
    creating_deployment_generation: u64,
    creating_effect_fence_epoch: u64,
    capsule_scope: ReplayCapsuleScopeV2,
    capsule_kind: ReplayCapsuleKindV2,
    key_binding: ReplayCapsuleKeyBindingV2,
    plaintext_length: u32,
    plaintext_digest: Digest32,
    committed_transaction_sequence: u64,
    created_at: UnixMillis,
    expires_at: UnixMillis,
}

struct SealedReplayCapsuleV2 {
    aad: ReplayCapsuleAadV2,
    nonce: FixedBytesV2<24>,
    ciphertext_and_tag: BoundedBytesV2<8_MiB_plus_16>,
    capsule_digest: Digest32,
}

struct ActionIntentEmissionRecordV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    key: ActionIntentEmissionKeyV2,
    stable_proposal_digest: Digest32,
    action_intent_handle_token_digest: Digest32,
    action_intent_handle_resolver_typed_hash: Digest32,
    projection_rule_digest: Digest32,
    capsule: SealedReplayCapsuleV2,
    capsule_digest: Digest32,
    state: InternalEmissionRecordStateV2,
    created_at: UnixMillis,
    expires_at: UnixMillis,
    record_digest: Digest32,
}

struct ActionIntentProjectionIndexV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    action_intent_id: ActionIntentIdV2,
    projection_version: u64,
    current_state_tag: u16,
    state_payload_digest: Digest32,
    child_emission_key: Option<ActionStateEmissionKeyV2>,
    child_emission_record_digest: Option<Digest32>,
    prior_projection_record_digest: Option<Digest32>,
    record_digest: Digest32,
}

struct ActionStateEmissionRecordV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    key: ActionStateEmissionKeyV2,
    canonical_intent_projection_record_digest: Digest32,
    child_token_digest: Digest32,
    child_resolver_typed_hash: Digest32,
    capsule: SealedReplayCapsuleV2,
    capsule_digest: Digest32,
    state: InternalEmissionRecordStateV2,
    created_at: UnixMillis,
    expires_at: UnixMillis,
    record_digest: Digest32,
}

struct ExecutionDocumentEmissionRecordV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    key: ExecutionDocumentEmissionKeyV2,
    execution_status_index_record_digest: Digest32,
    document_internal_digest: Digest32,
    document_token_digest: Digest32,
    document_resolver_typed_hash: Digest32,
    capsule: SealedReplayCapsuleV2,
    capsule_digest: Digest32,
    state: InternalEmissionRecordStateV2,
    created_at: UnixMillis,
    expires_at: UnixMillis,
    record_digest: Digest32,
}

struct MutationReplayRecordV2 {
    lookup_key_digest: Digest32,
    request_digest: Digest32,
    operation_tag: u16,
    operation_class: OperationClassV2,
    bound_internal_object_id: Digest32,
    response_commitment: ReplayResponseCommitmentV2,
    capsule: SealedReplayCapsuleV2,
    state: ReplaySlotStateV2,
    committed_transaction_sequence: u64,
    created_at: UnixMillis,
    expires_at: UnixMillis,
}
```

```text
RequestDigest =
  SHA-256("SAVANA_REQUEST_V2\0" || exact_canonical_request_bytes)

ReplayLookupKeyDigest =
  SHA-256("SAVANA_REPLAY_LOOKUP_KEY_V2\0" ||
          canonical_cbor(ReplayLookupKeyV2))

ReplayCapsuleContextDigest =
  SHA-256("SAVANA_REPLAY_CAPSULE_CONTEXT_V2\0" ||
          canonical_cbor(ReplayCapsuleContextV2))

ReplayCapsuleAadBytes =
  "SAVANA_REPLAY_CAPSULE_AAD_V2\0" ||
  canonical_cbor(ReplayCapsuleAadV2)

ReplayCapsulePlaintextDigest =
  SHA-256("SAVANA_REPLAY_CAPSULE_PLAINTEXT_V2\0" ||
          canonical_cbor(ReplayCapsuleMaterialV2))

ciphertext_and_tag =
  XChaCha20-Poly1305.seal(exact_resolved_capsule_key,
                         fresh_random_nonce_bstr24,
                         ReplayCapsuleAadBytes,
                         canonical_cbor(ReplayCapsuleMaterialV2))

ReplayCapsuleDigest =
  SHA-256("SAVANA_REPLAY_CAPSULE_V2\0" ||
          canonical_cbor([ReplayCapsuleAadV2,
                          nonce,
                          ciphertext_and_tag]))
```

Every service has a distinct fresh boot key for each implemented
`ReplayKeyRoleV2`; a key is never shared across endpoint or browser roles.
The durable agentd escrow is a separate deployment-locked key family, not a
boot role key. The complete AAD binds the full
installation, issuer service, closed client-replay or internal-emission
context, response schema,
creating manifest/generation/fence,
plaintext length/digest, kind, scope, the closed
`ReplayCapsuleKeyBindingV2`, transaction, and
retention window. A capsule copied between clients, peers, roles, operations,
objects, manifests, or scopes cannot open. The opener verifies canonical
plaintext length and `ReplayCapsulePlaintextDigest` before selecting its
closed material decoder.

`BootFresh` requires `ReplayCapsuleScopeV2::BootScoped`, the exact current
`BootReplayKeyRuntimeRecordV2`, and a capsule kind permitted by its manifest
policy; it can never protect `DurableTaskHandleEmission`.
`AgentdDurableEscrow` requires
`ReplayCapsuleScopeV2::DurablePrepareIngress`, the exact embedded deployment
lock digest/epoch/key ID, and exactly `DurableTaskHandleEmission`. Every
cross-pair is noncanonical.

`ReplayCapsuleContextV2::ClientReplay` requires the exact lookup key, request,
operation, authenticated client/boot/peer, and bound object shown; it is the
only context accepted from `MutationReplayRecordV2`.
`InternalEmission` has no request, operation, caller, client boot, OS peer, or
sentinel substitute. It requires the exact internal emission key, owning
object, immutable state revision, and material digest recorded by the
action-intent/action-state/execution-document store. A client replay record
cannot name `InternalEmission`, and an internal emission record cannot name
`ClientReplay`.

For daemon UDS roles, `ReplayClientIdentityV2::Daemon` and
`client_boot_id=Some(authenticated ClientHello.client_boot_id)` are mandatory.
JarvisAgentControl uses `Jarvis` and the authenticated control-process boot as
`Some`; it is reauthenticated on every connection. Browser roles use
`Browser` and `client_boot_id=None`;
`browser_replay_binding_digest` must equal
`SHA-256("SAVANA_BROWSER_REPLAY_BINDING_V2\0" ||
canonical_cbor(BrowserReplayBindingV2))` for the exact tab, typed one-way
capability, or selector in `BrowserMutationReplayKeyV2`. Every other
variant/boot-presence/binding combination is rejected before
replay lookup. In a durable tag-10 capsule,
`originating_client_boot_id` records the first control-process boot for audit
and AAD only; a later cross-boot retry is not required to equal it. The retry
reauthenticates the current principal and OS peer against the durable semantic
key rather than pretending to be the originating boot.

Only `ReplayCapsuleContextV2::ClientReplay` is accepted by a mutation
replay lookup. `InternalEmission` contexts exist solely in the action-state or
execution-document stores and have no caller key, request-replay slot, or
mutation lookup path. Conversely, a client replay key cannot select an
internal emission record.

The 24-byte XChaCha nonce is generated only by the service CSPRNG. In the same
local transaction as the replay record, the issuer durably reserves the exact
`(installation_id, issuer_service_identity,
ReplayCapsuleKeyBindingV2, nonce)` tuple in a uniqueness index. A collision is rejected
before mutation and a fresh nonce is drawn; an already committed tuple is
never reused, including after crash, rollback, replay, key retirement, or
capsule corruption. Caller, request, task, digest, counter, timestamp, and
deterministic test helpers cannot supply a production nonce.

The replay slot, semantic mutation, capability
reservation/consumption, quota, task status, response commitment, and sealed
capsule commit atomically. Capacity comes only from
`HardLimitsV2::COMPILED` and the signed resource profile; it is not a key-lock
field. Full capacity returns `Overloaded` before mutation. Active unexpired
records are never evicted.

Internal emission capacity is separately pre-reserved. `ProposeToolCall`
reserves its action-intent record, initial action-state child record, resolver,
and client replay row before creating the intent; every later intent-state
transaction reserves its next child emission before changing canonical state;
tool-result commit reserves the execution-document emission before publishing
success; browser view/action transactions reserve all object-reference
commitments and any cursor emission before consuming a cursor or changing
state. Reservation failure returns `Overloaded` with no semantic mutation.
There is no LRU, emergency eviction, overwrite, or capacity borrowing between
client replay, action-intent, action-state, execution-document, browser
object-reference, parser, or codec stores. An internal emission is collected
only after no live replay/index/status record can name it and its resolver
token has expired or been consumed; its tombstone remains through the maximum
parent retention deadline.

The capsule subsystem has no wire type, route, API, generic “decrypt,” export,
debug, or caller-selected decoder. Only an operation-specific dispatcher,
after authenticating the connection and finding an exact active replay
key/request/operation/client/peer/object match, may select the compiled
capsule kind and ask its role-specific opener to decrypt. Decrypted bytes stay
in zeroizing storage and are cleared after response encoding or any error.
`ExactResponseSnapshot` is allowed only for a response schema containing no
capability token and is returned as opaque byte-exact response bytes; it is
never parsed as a capability response.

`TypedCapabilityResponseEmission` is accepted only by the named operation's
compiled response decoder. Before any token byte is emitted, the dispatcher
must find every `CapabilityResolverCommitmentV2` in the current resolver,
recompute the exact token digest and type-separated resolver hash, and require
equality. `browser_object_ref_commitments` must contain exactly one strictly
ordinal-sorted entry for every object ref emitted by the closed agentd-owned
8768 ReadView or action response and no extra entry; it is empty for every
response variant with no object ref and for every non-agent-browser role.
The permitted ref types must equal the response matrix—for example planner
only step refs, dispatch only its execution/release ref, and refresh only the
same target plus the tool-success document ref. Agentd rechecks each local
object-record ID, immutable binding
revision, ref type, ref digest, and typed resolver hash before replay; a
missing/duplicate/mismatched entry poisons the slot and emits no partial
response. `ActionIntentHandleEmission` and `DurableTaskHandleEmission` apply
the same rule to their one named handle;
`ActionStateHandleEmission` applies it to the exact child named by the current
intent revision. The capsule is recovery material,
never a resolver: a missing, expired, wrong-type, or mismatched resolver row
fails stop and no row, token, task, intent, selector, or status is recreated.
An AEAD, canonical, digest, kind, commitment, or resolver failure atomically
marks the owning record `Poisoned`, returns only `ServiceUnavailable`, and
never reruns the original mutation. For `ClientReplay` this is the exact
`MutationReplayRecordV2.state=ReplaySlotStateV2::Poisoned`; for
`InternalEmission` it is only the named action-intent, action-state, or
execution-document emission record with
`state=InternalEmissionRecordStateV2::Poisoned`—there is no fabricated
mutation slot. Every lookup through an owning projection/status index must
resolve the exact named emission record and fail stop on `Poisoned`; it cannot
bypass, replace, or regenerate that record. An operation
30 query may make only that fail-stop poison write and emits no handle or
semantic state change. A poisoned record cannot be overwritten or reopened.

The first canonical request is the only transition winner. The same lookup
key with the same request digest follows its capsule path; a different digest
returns `IdempotencyConflict`. Concurrent identical requests observe one
transition. Query operations consume no replay capacity. Replay lookup occurs
before applying a new deadline to an already committed request. No transport,
client library, browser script, daemon, or recovery worker automatically
retries a mutation.

`ProposeToolCall` never stores `current` in an exact snapshot. The winning
transaction creates one boot-bound `ActionIntentEmissionKeyV2`, seals the
stable action-intent ID, random handle, typed resolver commitment, and
projection-rule digest in the corresponding internal
`ActionIntentHandleEmission`, and stores only an
`ActionIntentEmissionReference` in the client replay capsule. On replay,
under the intent and replay locks in one serializable transaction, kerneld
first opens that reference, requires the exact internal record and current
typed resolver row, then reads `ActionIntentCurrentStateV2` and its
monotonically increasing projection version from the canonical intent index
and follows that exact revision's optional `ActionStateHandleEmission`
capsule. Proposed,
Evaluating, and AwaitingApproval require a typed pending-handle emission;
Authorized requires an execution-ticket emission; Dispatched requires an
execution-handle emission; Terminal requires the same typed execution-handle
emission; Denied alone requires no child capsule.
Kerneld opens the child only through the same operation-specific dispatcher
and verifies its typed resolver row. A missing, extra, wrong-version,
wrong-state, or unresolvable child fails stop. The dispatcher then constructs
the response and atomically updates the replay record's
`last_emitted_projection_version` and `last_emitted_response_digest`.
`response_commitment` therefore binds the stable material, named projection
rule, and actually emitted current version; it never claims the old response
bytes are still current.

A new request ID with the byte-exact same semantically validated proposal may
resolve through the durable intent index to the same intent only from the
same authenticated agentd logical identity/client boot and current kerneld
boot fixed by `ActionIntentEmissionKeyV2`. It opens that existing internal
record and uses the same handle and projection rule without recreating
pending state. A different client, agentd boot, kerneld boot,
manifest/generation, proposal digest, missing record, or resolver mismatch
fails stop; it never re-mints the handle or rewrites the internal record.

```text
ActionIntentEmissionRecordDigest =
  SHA-256("SAVANA_ACTION_INTENT_EMISSION_RECORD_V2\0" ||
          canonical_cbor(record excluding record_digest))

ActionIntentProjectionIndexRecordDigest =
  SHA-256("SAVANA_ACTION_INTENT_PROJECTION_INDEX_V2\0" ||
          canonical_cbor(record excluding record_digest))

ActionStateEmissionRecordDigest =
  SHA-256("SAVANA_ACTION_STATE_EMISSION_RECORD_V2\0" ||
          canonical_cbor(record excluding record_digest))
```

Every state transaction increments `projection_version` exactly once and
atomically writes its canonical projection-index record. The child matrix is
closed:

| `ActionIntentCurrentStateV2` | Required child emission |
|---|---|
| `Proposed` | `ProposedPending` / one `PendingToolCallHandleV2` |
| `Evaluating` | `EvaluatingPending` / the exact same typed pending handle |
| `Denied` | none |
| `AwaitingApproval` | `AwaitingApprovalPending` / one typed pending handle |
| `Authorized` | `AuthorizedExecutionTicket` / one `ExecutionTicketHandleV2` |
| `Dispatched` | `DispatchedExecution` / one `ExecutionHandleV2` |
| `Terminal` | `TerminalExecution` / the same typed execution handle |

`Dispatched` contains only `ActionIntentDispatchPhaseV2`; `Terminal` contains
only `ActionIntentTerminalSummaryV2`. Neither embeds
`PublicExecutionStatusV2`, a document handle, or another random capability.
The transaction that first creates or reuses the required child also seals
one `ActionStateHandleEmission`, inserts the unique
`ActionStateEmissionKeyV2`, and records its digest in the canonical intent
index. Denied writes both child options as `None`. Missing, extra,
wrong-kind, wrong-version, cross-intent, or duplicate-key rows are corruption
and fail stop.

The action-state store is internal to kerneld and has no operation, route,
generic opener, or resolver. The parent Propose dispatcher may open only the
exact key named by the current canonical index and only after the parent
replay hit. It rechecks manifest/generation, index-record digest, token digest,
typed resolver hash, and current boot. Cross-manifest/boot reads are denied;
an old child cannot be carried by a replay compatibility edge. Historical
records are retained while any current-boot Propose replay can name them, then
are collected with the intent/handle retention DAG.

For tool-result success, the same kernel transaction that commits the masked
document creates its one random `MaskedDocumentHandleV2`, typed resolver row,
`ExecutionDocumentHandleEmission` capsule, unique
`ExecutionDocumentEmissionKeyV2`, and
`ExecutionDocumentEmissionRecordV2`, then points the canonical execution
status revision at that record. Its record digest is
`SHA-256("SAVANA_EXECUTION_DOCUMENT_EMISSION_RECORD_V2\0" ||
canonical_cbor(record excluding record_digest))`.

The status/handle combination matrix is:

| Operation/status | Required sealed emission |
|---|---|
| operation 30 `Succeeded(ToolExecution)` | exactly one matching execution-document emission |
| operation 30 any non-success terminal or nonterminal | none |
| operation 35 `Succeeded(FinalRelease)` | none |
| operation 35 any other legal release status | none |
| operation 30 `Succeeded(FinalRelease)` or operation 35 `Succeeded(ToolExecution)` | illegal cross-branch combination |

Operation 30 is a query only because it creates no token. It may open solely
the emission record named by the exact current execution-status index and
must recheck operation role/tag, status revision, outcome commit, token
digest, typed resolver hash, manifest/generation, and current boot before
returning the already-created handle. Operation 29 and the 8768
dispatch response are restricted to `Prepared` or `Dispatching` and cannot
open this capsule. Only operation 30 may open it; agentd then creates any
browser non-capability document reference inside the separate replay-identified
Refresh mutation. Missing, extra, cross-operation, or cross-branch records
fail stop; no query stores plaintext, re-mints a handle, or uses the Propose
child capsule. Final-release success never has a document emission.

AgentKernel operation 31 is a `SensitiveIdempotentMutation`, not a query. Its
request carries `client_request_nonce`; the first request atomically consumes
the input cursor when present, computes the exact bounded view, creates at
most one random next `KernelAgentViewCursorV2` and typed resolver row, and
stores a `TypedCapabilityResponseEmission` replay capsule. Exact replay emits
the same view/cursor only after the resolver commitment verifies. A changed
document, input cursor, byte limit, or request bytes under the replay key is
`IdempotencyConflict`.

The 8768 `ReadView` request is likewise replay-identified by
`(tab, client_request_nonce, canonical request)`. Before calling operation 31,
agentd reserves one stable kernel request nonce in its local browser replay
record. It then atomically publishes the browser response, random typed
object references, and at most one
`AgentBrowserViewCursorCapabilityV2` through its own typed-capability capsule.
A crash between the two daemons replays operation 31 with the stable nonce;
it never asks kerneld or agentd to mint another cursor. Kernel and browser
cursor emissions are role/operation separated and cannot open each other.

Consequently, every operation classified `Query` creates no random handle.
Every path that first creates a pending/ticket/execution/document/cursor
handle is either an idempotent mutation with a typed replay emission or a
state transaction that pre-stores the closed operation-specific emission
before a later query. Hash-only resolver rows are never treated as recoverable
token storage.

JarvisAgentControl tag 10 first atomically creates its local
`AgentdPrepareIngressRecordV2::Reserved` semantic row; it does not yet have a
public handle or response capsule. After operation 38 is durably reconciled,
the final agentd `Published` transaction atomically creates the TaskHandle
resolver, mutation replay record, and durable capsule described here. The
durable capsule contains only
`DurableTaskHandleEmission`: the same random `TaskHandleV2`, its current
typed resolver hash, durable task, original request digest, signed
correlation digest, and the exact `query_tombstone_retain_until`. It never
contains a `JarvisBootstrapSelectorV2`, bootstrap URL, old status, kernel
capability, or full prior response. On a later agentd boot, the old selector
is invalid and cannot be reopened. After authenticating the durable key,
request digest, current TaskHandle resolver row, correlation, installation,
principal, and OS peer, agentd returns the same TaskHandle plus a current
closed bootstrap projection: `None` when no bootstrap is presently legal, or
the unique live selector at key
`(durable_task_id, current_agentd_boot_id, public_state_revision,
BootstrapKindV2)`. The projection transaction reuses that selector on every
replay; it creates at most one when absent and tombstones every prior-state
selector before publishing a changed public-state revision. It therefore
cannot mint an unbounded selector stream. The caller uses tag 11 for
authoritative current status. Thus
cross-boot tag-10 replay does not promise byte-identical response bytes.

The durable replay escrow key/epoch may open this one capsule kind only until
the exact `query_tombstone_retain_until`. At that instant the row becomes
`Expired`, the key dependency is released, and later open or reconstruction
is forbidden. Boot-scoped role keys are destroyed and verified unavailable at
every service restart; their old capsules cannot authorize anything. Durable
escrow across a manifest change is denied unless a named, directional
deployment `ReplayCapsuleCompatibilityEdgeV2` under the exact
`AgentdDurableReplayAeadLockV2`, fixed by the release-root-authorized
destination manifest and `ServiceIdentityLock` digest, permits the old
store/epoch through its `read-existing DurableTaskHandleEmission` capability.
Its store ID, persistent-store compatibility, protocol ABI, runtime AEAD role,
permitted epoch, retain-until, and edge identity must all match. Reverse,
transitive, wildcard, inferred, caller-supplied, or any other capsule-kind
compatibility is forbidden.

Finalize, planner commit, approval, claim, dispatch, UI-authentication
registration, and settlement-transfer replay use either a capability-free
exact snapshot or their compiled typed-capability emission and return only
after all resolver commitments verify. A changed purpose, origin, record,
transfer, challenge, assertion, decision, or subject is an idempotency
conflict. No UDS replay capsule stores WebAuthn options or assertions.

Boot-scoped replay does not create cross-restart authority. Durable semantic
indexes separately preserve task, action-intent, approval, execution nonce,
release, and terminal-state identities. Agentd alone owns the public
TaskHandle resolver and bootstrap-selector ledger; kerneld never decodes the
public handle. No old capability handle is accepted after restart, and status
recovery never reauthorizes a mutation.

### 10.1 Kernel atomic transaction and lock order

All kerneld security state uses one serializable durable transaction boundary
over replay, task/preparation/run/session, UI-authentication bindings,
values/provenance, approval ledger, quota, vault, action intent, dispatch
WAL/index, kernel task status, and audit precommit.
If physically separate stores are used, one write-ahead transaction record
and recovery protocol makes their visibility all-or-none before any response
or external byte.

The global lock order is:

```text
agentd EffectGate shared guard for operations 29/34 (caller process only)
  → authenticated AgentKernel request boundary
  → deployment fence
  → durable task
  → task/UI-authentication preparation
  → run/session
  → plan step/action intent
  → pending approval/ticket
  → vault segment
  → dispatch nonce
  → replay slot
  → audit precommit
```

`CancelKernelTask`, `RevokeVault`, `CloseAgentSession`,
`DispatchExecution`, and `DispatchRelease` acquire the same
deployment/task/preparation/run/intent/vault/dispatch locks and revalidate
state inside the transaction. If cancel/revoke/close
commits first, dispatch writes no byte and returns `StateConflict`. If
dispatch preparation or any possible external byte commits first, the
destructive operation returns `CancellationTooLate` or `StateConflict` and
cannot alter authorization, nonce, quota, or result state. No check-then-act
split or second store transaction is conforming.

### 10.2 EffectGate coordinator and fenced reconciliation

Agentd and execd each own one process-wide
`EffectGateLeaseCoordinatorV2`. It is internal state, never a wire object or
caller-controlled lock mode. A coordinator contains a mutex, an active-holder
count, the one service-manager-injected read-only/shared-only gate descriptor,
and the one fixed read-only authenticated ledger-projection descriptor.
The first holder under the mutex acquires the process-associated POSIX
`F_RDLCK` with `F_SETLKW`; later holders increment
the count without issuing another kernel lock; a completion decrements the
count, and only the transition from one to zero may issue `F_UNLCK`.
Cancellation, unwind, descriptor close, fork/exec, and service shutdown use
the same coordinator path. Per-operation unlock on the shared descriptor is
forbidden. Linux and macOS both use the deployment-defined
process-associated POSIX `F_SETLK`/`F_SETLKW` mechanism; OFD locks, `flock`,
and per-thread/per-open-file-description substitutes are forbidden because
they do not implement the deployment's process ownership and manager-retained
descriptor semantics. Repeated record-lock acquisition is not a lease
reference count.

After the first shared acquisition and before publishing a planner marker,
execd `Prepared`, or any possible external byte, the service re-reads the
fixed projection and authenticates installation, selected manifest,
deployment generation, effect-fence epoch, terminal/unfenced phase, signature,
and projection identity. Neither service can traverse, open, receive, or read
the root ledger path/slots, and neither receives a writable ledger,
projection, selector, gate, or root-directory descriptor. A projection
refresh must complete under the deployment exclusive lease before that lease
is released; a stale/torn/noncanonical projection fails closed.

Agentd holds one coordinator reference from its durable planner marker through
durable response/failure reconciliation. The marker binds the exact agentd
service/boot/process identity, planner request, manifest/generation/fence,
compiled deadline, and marker digest. At expiry helper/watchdog may terminate
only the exact service-manager unit/job and descendants identified by
pidfd/start identity or audit-token/start identity. Agentd alone, restarted in
fenced recovery mode, writes the canonical failed/indeterminate terminal for
that marker. A late planner response is rejected, and no replacement planner
request is created.

```rust
enum AgentEffectAdmissionKindV2 {
    Planner = 1,
    DispatchExecution = 2,
    DispatchRelease = 3,
}
```

The 8768 browser action handler also acquires the same process-wide agentd
coordinator before invoking AgentKernel operation 29 or 34. It holds that one
shared reference across the kernel request, a durable kernel success/failure
response, and agentd's corresponding replay/public-state commit. Connection
loss keeps the reference held while agentd reconciles the same durable intent
or release; it does not issue a second mutation. If agentd crashes, the OS
releases its shared lock and the deployment snapshot must include any WAL row
kerneld committed before the crash.

This caller guard is outer to all kerneld locks in section 10.1 and is never
acquired or released inside a kerneld transaction. Once deploy/watchdog owns
the exclusive gate, no live browser handler can enter operation 29/34 and
create a new `Prepared` WAL row during ARMED-set enumeration. Kernel recovery
resend applies only to a WAL row already present in the frozen set and only
through the owner recovery mode below; it is not a new browser admission.

Execd takes one coordinator reference before `Prepared`, retains it through
the connector and durable terminal/indeterminate journal record, and releases
it only afterward. Connector retry is disabled unless the exact signed
descriptor selects
`ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce` and a
compiled `BoundedConnectorRetryPolicyV2 { maximum_attempts: u16,
maximum_elapsed_ns: u64 }`. Such a provider retry is owned internally by execd,
bounded by both fields, occurs while the same coordinator reference remains
held, and reuses byte-for-byte the same execution nonce, dispatch core,
subject, sealed execution record, connector identity, and credential
binding. Non-idempotent descriptors have exactly one attempt. Kerneld,
agentd, transports, timeout handlers, and recovery code never automatically
retry a connector or create a replacement nonce.

The deployment freeze uses only the deployment-defined
`FrozenEffectWorkKindV2`, `FrozenEffectWorkItemV2`, and
`FrozenEffectWorkSetV2`; protocol defines no alternate head/set schema or
aggregate digest. Each owner projects every complete nonterminal operation
visible at its authenticated durable head into exactly one deployment item:

| Owner store | Deployment kind | `durable_operation_id` | `nonce_or_request_digest` | authenticated head/state |
|---|---|---|---|---|
| agentd planner-marker journal | `AgentdPlannerMarker` | exact marker record digest | exact planner request digest | marker-journal head and marker phase tag |
| kerneld dispatch WAL | `KerneldDispatchWalHead` | exact WAL record/dispatch-core identity digest | hash of the exact execution nonce | WAL head and `KernelDispatchStateV2` tag |
| execd journal | `ExecdJournalHead` | exact executor record identity digest | hash of the exact execution nonce | executor journal head and `ExecutorJournalStateV2` tag |

For execd, `ProviderAttemptPrepared`, `ProviderRetryPrepared`,
`EffectStarted`, `ProviderResponseRetained`, `ReleaseEvidencePrepared`, and
`CompletionAvailable` are distinct nonterminal head tags and each must project
as the exact current `ExecdJournalHead`; a freeze cannot collapse one into
another or infer no effect from a retry-prepared head. Its owner-only terminal
descendant must preserve the prior effect receipt and choose spent,
indeterminate-spent, or acknowledged known-success quota semantics as
applicable; it can never release quota from a chain containing
`EffectStarted`.

The complete item array is strictly sorted by the deployment registry key
`(kind, owning_service, durable_operation_id,
authenticated_head_digest)`, rejects duplicates, and hashes only with the
deployment registry domain for `frozen_effect_work_set_digest`. An operation
present in two stores produces two typed owner items; neither may suppress the
other as “the same nonce.” While holding the exclusive gate, deploy/watchdog
installs and measures the OS deny-all fence, captures those already durable
authenticated heads, and binds the exact deployment
`FrozenEffectWorkSetV2.frozen_effect_work_set_digest` into `ARMED`.
Exclusive acquisition proves only that no live shared holder remains; it does
not prove that a crash-released marker or `EffectStarted` is terminal.

After the `ARMED` ledger record and OS fence are durable, the exclusive gate
may be released. Agentd, kerneld, and execd may then run only their fixed
ledger-plus-OS-double-fenced recovery modes. Each owner reads the bound
snapshot and writes/flushes terminal or public-indeterminate records only in
its own store. Deploy/watchdog may stop/start exact recovery jobs and verify
their authenticated heads, but it never fabricates, edits, appends, or signs
an agentd marker, kerneld WAL entry, execd journal entry, quota transition, or
terminal result. For every frozen item, its named owner must produce one
authenticated terminal descendant with the same operation identity and
nonce/request digest, a previous-record chain reaching the frozen
authenticated head, and a terminal state legal from the frozen observed tag.
Entry to `QUIESCED` requires exact set equality between the frozen items and
those owner-authenticated terminal descendants—no omission, extra record,
owner substitution, head substitution, opaque set summary, or “lock acquired
therefore clean” shortcut is accepted.

## 11. Action intent, quota, approval, and tool-call state

### 11.1 Action intent

kerneld validates the closed planner graph and atomically commits one immutable
`PlanStepRecordV2` per ordinal:

```rust
struct PlanStepRecordV2 {
    durable_run_id: DurableRunIdV2,
    plan_revision_digest: PlanRevisionDigestV2,
    internal_step_id: InternalStepIdV2,
    action_template: ActionTemplateIdV2,
    required_tool_class: ToolClassIdV2,
    argument_bindings:
        BoundedSortedVec<ResolvedPlannerArgumentBindingV2, 256>,
    dependency_step_ids: BoundedSortedVec<InternalStepIdV2, 256>,
}
```

Planner commit returns only boot-bound `PlanStepHandleV2` values. It creates no
action intent, pending call, approval, ticket, quota reservation, or execution
nonce.

On the first valid `ProposeToolCall` for a step, kerneld resolves the exact
active descriptor, requires its action template/tool class to equal the step,
requires the strictly sorted unique arguments to match the descriptor and
step slot mapping, resolves every value handle to the stored immutable
`(InternalSlotDigestV2, ValueInternalIdV2, ValueDigest, ProvenanceDigest)`
binding, rechecks every internal-slot digest and label, and then computes:

```text
ActionIntentId =
  SHA-256("SAVANA_ACTION_INTENT_V2\0" ||
          installation_id ||
          active_state_manifest_digest ||
          durable_run_id ||
          durable_task_id ||
          ToolExecutionSemanticBindingDigest)
```

The intent record, action ID, selected descriptor, normalized arguments,
stable value/provenance tuples, destination/display projections, token set,
executor identity, pending-call state, replay record, and public task state
are created in one atomic transaction. agentd receives only boot-bound opaque
`ActionIntentHandleV2` and `PendingToolCallHandleV2` values.

The same validated revision/internal-step binding has at most one intent.
Exact `ProposeToolCall` replay, or a new request ID carrying the byte-exact
same proposal, returns the same intent together with its current canonical
`ActionIntentCurrentStateV2`. That state may already be denied, awaiting
approval, authorized, dispatched, or terminal; replay never recreates or
resets a pending call. Reusing one proposal request ID with different
canonical bytes returns `IdempotencyConflict`. Attempting to bind an already
bound internal step to a changed descriptor, argument
name/order/value/provenance, tool class, or active-state binding returns
`StateConflict`; neither case creates a second intent, approval, ticket, or
nonce.

A different fresh, kernel-validated plan revision/internal step may create a
new intent only when policy, attempt, and quota rules allow it. The old intent
remains immutable and can never acquire a replacement execution nonce,
including after denial, failure, uncertainty, or terminal completion.

### 11.2 Tool-call state

```text
PlanStepReady → Proposed → Evaluating
                           ├──→ Denied
                           ├──→ NeedsApproval → AuthorizedApproval ──┐
                           └──→ AuthorizedPolicy ─────────────────────┤
                                                                     ↓
                 DispatchPrepared → Dispatching
                                      ├──→ FailedNoEffect
                                      ├──→ Indeterminate
                                      └──→ ResultGatePending
                                             ├──→ Succeeded
                                             └──→ EffectSucceededOutputQuarantined
```

`Succeeded`, `EffectSucceededOutputQuarantined`, `FailedNoEffect`, and
`Indeterminate` are terminal and cannot return to an earlier state.
`EffectSucceededOutputQuarantined` means the external effect definitely
occurred, quota is spent, the nonce can never be reused, no automatic or
manual redispatch is allowed, and result bytes remain encrypted in execd until
acknowledged quarantine handling or bounded expiry.

The `Audit` failure class is mandatory when the effect outcome and result are
known but kerneld cannot durably publish the required audit outcome. The
public task, execution, durable outcome, and kernel dispatch state all become
`EffectSucceededOutputQuarantined { class: Audit }`; no agent-readable
document is created and execd retains the encrypted result. `Indeterminate`
is reserved exclusively for an effect outcome that cannot be proved, never
for failure to store or publish audit after known effect success.

`PlanStepReady` is a plan-step state, not an action-intent state. `Proposed`
is the first action-intent state and is reached only by the atomic creation
above. Evaluate executes G3→G4→the exact internal
G5 validator set→G6 under one state transaction. It accepts no attestations or
external validator result. Its stored decision is returned on replay.
`NeedsApproval` becomes visible only after kerneld has signed, reverified, and
stored the exact envelope digest.

Approval ledger:

```text
Unused → Reserved(intent,ticket) → Consumed
                              └──→ ConsumedExpired
```

Authorize accepts only an exact approved settlement matching the stored
envelope. Exact replay returns the same ticket. Deny or expiry makes the
intent terminal without authority.

### 11.3 Quota

Quota subjects are closed by dispatch branch. A final release never borrows,
aliases, or fabricates a tool `AttemptKindV2`:

```rust
enum DispatchQuotaSubjectV2 {
    ToolAttempt {
        attempt_kind: AttemptKindV2,
    } = 1,
    FinalRelease {
        release_quota_subject_digest: Digest32,
    } = 2,
}

struct DispatchQuotaCounterV2 {
    reserved: u32,
    spent: u32,
}

struct DispatchQuotaReservationV2 {
    durable_run_id: DurableRunIdV2,
    quota_subject: DispatchQuotaSubjectV2,
    dispatch_subject_digest: Digest32,
    execution_nonce: Nonce32,
    state: DispatchQuotaReservationStateV2,
}

enum DispatchQuotaReservationStateV2 {
    Reserved = 1,
    Spent = 2,
    ReleasedNoEffect = 3,
    IndeterminateSpent = 4,
}
```

Tool limits are indexed by `(run, ToolAttempt(attempt_kind))`. Release limits
are indexed by `(run, FinalRelease(release_quota_subject_digest))`, where the
digest comes from the immutable signed release-policy decision and is already
bound by `FinalReleaseSemanticBindingV2`. Cross-variant lookup or counter
sharing is rejected.

Admission requires:

```text
reserved + spent < effective_limit
```

Dispatch preparation increments `reserved` and creates exactly one
`DispatchQuotaReservationV2` for the subject/nonce. While delivery or effect state
is being reconciled, kerneld keeps that reservation and forbids every new
nonce for the tool intent or durable final release. The reservation transition
matrix is exact:

| Authenticated effect disposition | Reservation transition | Counter delta |
|---|---|---|
| first valid `EffectStarted`, or known success if that receipt is recovered first | `Reserved → Spent` | `reserved -= 1; spent += 1` |
| terminal unprovable effect outcome before a prior spent transition | `Reserved → IndeterminateSpent` | `reserved -= 1; spent += 1` |
| terminal unprovable effect outcome after `EffectStarted` already spent | `Spent → IndeterminateSpent` | no counter delta |
| `FailedNoEffect` with no effect-start receipt and zero-byte/closed proof where required | `Reserved → ReleasedNoEffect` | `reserved -= 1; spent unchanged` |

If `Spent` was recorded at `EffectStarted`, later success, quarantine, or
completion acknowledgement leaves it `Spent` and does not touch counters;
terminal unprovable recovery changes only its state to
`IndeterminateSpent`, also with no counter delta.
`IndeterminateSpent` and `ReleasedNoEffect` are terminal reservation states.
An effect-started or known-success nonce can never transition to
`ReleasedNoEffect`; a failed-before-effect nonce can never transition to a
spent state without a later independently authenticated effect-start record.
The state change, counter delta, WAL/public outcome, and no-new-nonce
tombstone commit in one transaction, so crash replay applies no delta twice.

Only proof of exactly zero bytes passed to the OS plus authenticated execd
status `Unknown` carrying a valid complete nonce-absence proof may permit an
explicit byte-exact resend of the same nonce; the attempt remains reserved
through that decision. Any other unresolved delivery stays reserved and
blocks progress until reconciliation proves `EffectStarted`, known success,
`FailedNoEffect`, or terminal `Indeterminate`, at which point the local
transaction applies the rule above to that exact subject. No state path
creates a new nonce for that intent or release. A denied or expired
authorization that was never dispatch-prepared does not spend quota.

### 11.4 Approval, agent-UI authentication, and WebAuthn ABI

```rust
enum ApprovalPurposeV2 {
    Ingress = 1,
    ToolExecution = 2,
    FinalRelease = 3,
}

enum ApprovalDecisionV2 {
    Deny = 1,
    Approve = 2,
}

enum ApprovalBindingV2 {
    Ingress {
        pending_ingress_id: Digest32,
        ingress_subject_digest: Digest32,
        channel_commitments_digest: Digest32,
        source_provenance_digest: Digest32,
    } = 1,
    ToolExecution {
        action_intent_id: ActionIntentIdV2,
        binding: ToolExecutionSemanticBindingV2,
    } = 2,
    FinalRelease {
        binding: FinalReleaseSemanticBindingV2,
    } = 3,
}

struct UnsignedApprovalEnvelopeV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    purpose: ApprovalPurposeV2,
    envelope_nonce: Nonce32,
    decision_challenge: Nonce32,
    binding: ApprovalBindingV2,
    expected_principal: PrincipalIdV2,
    display_projection_digest: Digest32,
    display_digest: Digest32,
    approvald_endpoint_identity: ServiceIdentityV2,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}

struct UnsignedApprovalSettlementV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    purpose: ApprovalPurposeV2,
    envelope_digest: Digest32,
    decision: ApprovalDecisionV2,
    authenticated_principal: PrincipalIdV2,
    authentication_context_digest: Digest32,
    credential_digest: Digest32,
    user_present: bool,                  // exactly true
    user_verified: bool,                 // exactly true
    backup_eligible: bool,               // exactly false
    backup_state: bool,                  // exactly false
    signature_counter: u32,              // strictly greater than stored value
    challenge: Nonce32,
    settlement_nonce: Nonce32,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}
```

`SignedApprovalEnvelopeV2` and `SignedApprovalSettlementV2` use the signed
object representation in section 3.1. Exact signature inputs are:

```text
ApprovalEnvelopeDigest =
  SHA-256(approval_envelope_domain || payload_bstr)

ApprovalEnvelopeSignature =
  Ed25519.sign(kerneld_envelope_key,
               approval_envelope_domain || ApprovalEnvelopeDigest)

ApprovalSettlementDigest =
  SHA-256(approval_settlement_domain || payload_bstr)

ApprovalSettlementSignature =
  Ed25519.sign(approvald_purpose_key,
               approval_settlement_domain || ApprovalSettlementDigest)

purpose                approval_envelope_domain
Ingress                "SAVANA_INGRESS_APPROVAL_ENVELOPE_V2\0"
ToolExecution          "SAVANA_TOOL_APPROVAL_ENVELOPE_V2\0"
FinalRelease           "SAVANA_RELEASE_APPROVAL_ENVELOPE_V2\0"

purpose                approval_settlement_domain
Ingress                "SAVANA_INGRESS_APPROVAL_SETTLEMENT_V2\0"
ToolExecution          "SAVANA_TOOL_APPROVAL_SETTLEMENT_V2\0"
FinalRelease           "SAVANA_RELEASE_APPROVAL_SETTLEMENT_V2\0"
```

The ingress, tool, and release approval-settlement keys are distinct and each
may sign only its named approval domain. The fourth settlement-key family is
the dedicated UI-authentication key; it cannot sign an approval decision.
kerneld and approvald verify canonical payload bytes, domain, exact key ID,
active manifest/generation, purpose, challenge, expiry, principal, and every
binding field before state lookup.

The `ToolExecutionSemanticBindingV2` in an action-intent record, tool approval
binding, dispatch subject, kernel WAL, and sealed tool material is the same
canonical object and has one digest. The `FinalReleaseSemanticBindingV2` in a
durable release record, release approval binding, dispatch subject, kernel
WAL, and sealed release material follows the same rule. Every duplicated
projection, display, destination, token, evidence, vault, executor, argument,
provenance-set, plan-revision, and internal-step field must byte-equal that
object. No layer may re-resolve an alias, substitute a later handle target, or
reconstruct a semantically similar binding.

UI authentication is a separate signed protocol:

```rust
enum UiAuthenticationPurposeV2 {
    IngressInput = 1,
    ApprovalDisplay = 2,
    AgentContent = 3,
}

enum UiAuthenticationBindingV2 {
    IngressNewTask {
        durable_task_id: DurableTaskIdV2,
        pending_task_digest: Digest32,
        ingressd_identity: ServiceIdentityV2,
    } = 1,
    IngressExistingRun {
        durable_task_id: DurableTaskIdV2,
        durable_run_id: DurableRunIdV2,
        captured_run_revision_digest: RunRevisionDigestV2,
        ingressd_identity: ServiceIdentityV2,
    } = 2,
    ApprovalDisplay {
        durable_task_id: DurableTaskIdV2,
        approval_envelope_digest: Digest32,
        approval_purpose: ApprovalPurposeV2,
        display_digest: Digest32,
    } = 3,
    AgentContent {
        durable_task_id: DurableTaskIdV2,
        ingress_claim_digest: Digest32,
        agentd_identity: ServiceIdentityV2,
        agentd_boot_id: BootIdV2,
    } = 4,
}

struct UnsignedUiAuthenticationEnvelopeV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    purpose: UiAuthenticationPurposeV2,
    binding: UiAuthenticationBindingV2,
    expected_principal: Option<PrincipalIdV2>,
    authentication_origin: FixedOriginV2,
    return_origin: FixedOriginV2,
    envelope_nonce: Nonce32,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}

struct UnsignedUiAuthenticationSettlementV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    purpose: UiAuthenticationPurposeV2,
    envelope_digest: Digest32,
    binding_digest: Digest32,
    authentication_origin: FixedOriginV2,
    return_origin: FixedOriginV2,
    authenticated_principal: PrincipalIdV2,
    authentication_context_digest: Digest32,
    credential_digest: Digest32,
    user_present: bool,                  // exactly true
    user_verified: bool,                 // exactly true
    backup_eligible: bool,               // exactly false
    backup_state: bool,                  // exactly false
    signature_counter: u32,
    challenge: Nonce32,
    settlement_nonce: Nonce32,
    issued_at: UnixMillis,
    expires_at: UnixMillis,
}
```

`SignedUiAuthenticationEnvelopeV2` and
`SignedUiAuthenticationSettlementV2` use section 3.1. Purpose/origin/domain
mapping is exact:

| Purpose | WebAuthn authentication origin | Post-authentication origin | Envelope domain | Settlement domain |
|---|---|---|---|---|
| `IngressInput` | `http://localhost:8766` | `http://localhost:8767` | `"SAVANA_UI_AUTH_INGRESS_ENVELOPE_V2\0"` | `"SAVANA_UI_AUTH_INGRESS_SETTLEMENT_V2\0"` |
| `ApprovalDisplay` | `http://localhost:8766` | `http://localhost:8766` | `"SAVANA_UI_AUTH_APPROVAL_DISPLAY_ENVELOPE_V2\0"` | `"SAVANA_UI_AUTH_APPROVAL_DISPLAY_SETTLEMENT_V2\0"` |
| `AgentContent` | `http://localhost:8766` | `http://localhost:8768` | `"SAVANA_UI_AUTH_AGENT_ENVELOPE_V2\0"` | `"SAVANA_UI_AUTH_AGENT_SETTLEMENT_V2\0"` |

The kerneld envelope key signs
`domain || SHA-256(domain || payload_bstr)`. The dedicated approvald UI-auth
settlement key signs the same construction with the settlement domain.
`IngressNewTask` is the only binding that permits
`expected_principal=None`; it selects and durably binds the principal before
input authority exists. Every other binding requires `Some(principal)` and
the settlement principal must equal it.

For every authentication and approval-decision assertion, approvald enforces:

```text
RP ID                         exact ASCII "localhost"
UI-auth expected origin        exact "http://localhost:8766"
approval-decision origin       exact "http://localhost:8766"
authentication clientData type exact "webauthn.get"
enrollment clientData type     exact "webauthn.create"
clientDataJSON.challenge       exact unpadded-base64url stored challenge
clientDataJSON.crossOrigin     false
clientDataJSON.topOrigin       absent
authenticatorData.rpIdHash     SHA-256("localhost")
UP flag                        1
UV flag                        1
BE flag                        0
BS flag                        0
stored credential class       hardware, non-backup
credential COSE algorithm      ES256 / COSE alg -7 / P-256 only
credential AAGUID              exact ApprovalLock allowlist member
assertion signCount            nonzero and strictly greater than stored count
principal/user handle          exact envelope/session principal
```

Enrollment additionally requires direct hardware attestation whose chain
terminates in an exact root/AAGUID pair in `ApprovalLockV2`; self/none
attestation and synced passkeys are rejected. Assertion signature, strict DER,
curve point, low-S form, client-data hash, authenticator data, and credential
public key are verified only by the pinned implementation in that lock.
Unknown JSON members are ignored only as required by WebAuthn; duplicate keys
and unbounded members are rejected.

The authentication-context digest is:

```text
SHA-256("SAVANA_WEBAUTHN_CONTEXT_V2\0" ||
        purpose_u16be ||
        authentication_origin_u16be ||
        return_origin_u16be ||
        envelope_or_approval_digest ||
        SHA-256(exact_clientDataJSON_bytes) ||
        SHA-256(exact_authenticatorData_bytes) ||
        credential_digest ||
        signature_counter_u32be ||
        aaguid_bstr16)
```

UI authentication and approval decision are two ceremonies with independent
challenges, ceremony handles, settlement nonces, signature domains, replay
slots, and counter increments. After `ApprovalDisplay` UI authentication,
approvald atomically creates one hashed, tab-memory
`ApprovalTabSessionCapabilityV2`; only that session may fetch the bound
display. A later decision-begin POST binds `Approve` or `Deny`, atomically
reserves the exact previously unused envelope `decision_challenge`, and
creates `ApprovalDecisionCeremonyCapabilityV2`. Decision finish must
authenticate the same principal, advance the counter again, and only then
create `SignedApprovalSettlementV2`.

For ingress or agent UI authentication, approvald atomically advances the
counter and creates only `SignedUiAuthenticationSettlementV2`. It returns no
content-origin tab capability. Instead it creates a random, one-use,
purpose/record/return-origin-bound
`IngressUiAuthenticationSettlementTransferCapabilityV2` or
`AgentUiAuthenticationSettlementTransferCapabilityV2` and emits it only in
the fixed browser form POST to 8767 or 8768. The destination daemon consumes
that capability through UDS tag 23, obtains the exact already stored
settlement, and must then obtain matching kerneld authorization before
returning its `IngressTabSessionCapabilityV2` or
`AgentTabSessionCapabilityV2`.

The signed approval lock has this exact bounded ABI:

```rust
enum WebAuthnRpIdV2 {
    Localhost = 1,
}

enum SettlementKeyFamilyV2 {
    IngressApproval = 1,
    ToolApproval = 2,
    ReleaseApproval = 3,
    UiAuthentication = 4,
}

enum CredentialCounterPolicyV2 {
    StrictNonzeroIncrement = 1,
}

struct VerificationKeyEpochV2 {
    epoch: u64,
    key_id: Ed25519KeyIdV2,
    public_key: FixedBytesV2<32>,
    not_before: UnixMillis,
    verify_until: UnixMillis,
}

struct SettlementKeyFamilyLockV2 {
    family: SettlementKeyFamilyV2,
    active: VerificationKeyEpochV2,
    retired: BoundedVec<VerificationKeyEpochV2, 4>,
}

struct HardwareAttestationPairV2 {
    aaguid: FixedBytesV2<16>,
    direct_attestation_root_certificate_sha256: Digest32,
    direct_attestation_root_spki_sha256: Digest32,
}

struct EnrollmentProfileLockEntryV2 {
    profile: EnrollmentProfileIdV2,
    credential_lifetime_ms: u64,
    enrollment_ceremony_lifetime_ms: u64,
    authentication_ceremony_lifetime_ms: u64,
    counter_policy: CredentialCounterPolicyV2,
}

struct WebAuthnImplementationLockV2 {
    implementation_id: ImplementationIdV2,
    semantic_version: VersionV2,
    code_digest: Digest32,
    build_manifest_digest: Digest32,
}

struct ApprovalLockV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    lock_sequence: u64,
    previous_lock_digest: Digest32,
    rp_id: WebAuthnRpIdV2,              // exactly Localhost
    webauthn_origin: FixedOriginV2,      // exactly Approval8766
    ingress_return_origin: FixedOriginV2,// exactly Ingress8767
    approval_return_origin: FixedOriginV2,// exactly Approval8766
    agent_return_origin: FixedOriginV2,  // exactly Agent8768
    attestation_pairs:
        BoundedVec<HardwareAttestationPairV2, 256>,
    settlement_key_families:
        BoundedVec<SettlementKeyFamilyLockV2, 4>,
    enrollment_profiles:
        BoundedVec<EnrollmentProfileLockEntryV2, 64>,
    webauthn_implementation: WebAuthnImplementationLockV2,
    not_before: UnixMillis,
    expires_at: UnixMillis,
}
```

`attestation_pairs` sorts strictly by `(aaguid, root_certificate_sha256,
root_spki_sha256)`. Settlement families sort by family and contain exactly
the four values once; retired keys sort by epoch/key ID. Enrollment profiles
sort by profile. Every list rejects duplicates and unknown enum/profile
values. Each public key must recompute its exact `Ed25519KeyIdV2`.

```text
ApprovalLockDigest =
  SHA-256("SAVANA_APPROVAL_LOCK_V2\0" ||
          canonical_cbor(ApprovalLockV2))
```

`ApprovalLockV2` has no protocol-local inner signature. It is an immutable
deployment manifest component identified through the deployment-defined
`VersionedIdentityV2`, exact component signature set, and release-signed
`SecurityStateManifestV2`; approvald verifies that complete component binding
and the exact `ApprovalLockDigest`. Approvald takes the manifest/lock pair
from one verified deployment snapshot and uses no RP, origin, AAGUID, root,
key, profile, lifetime, counter policy, or WebAuthn implementation value from
any request or other configuration. Unknown, missing, duplicated, expired,
inner/bare-signature, or rollback lock data fails closed.

Settlement-key activation/retirement occurs only in the deployment rotation
transaction. The four family epochs and retired verification dependencies
participate in the same rotation DAG and maximum-four-retired-epochs rule as
section 17.5; a key required by a live envelope, settlement, credential,
ceremony, tombstone, or rollback reader cannot be deleted.

## 12. Ingress and vault state

Ingress:

```text
Granted
  → Receiving
  → Finalizing
  → AwaitingApproval
  → Committing
  → CommittedUnclaimed
  → AgentAuthPending
  → AgentClaimed

terminal before commit:
Denied | Aborted | Expired | FailedClosed | RestartInvalidated
```

Finalize is transactional. Awaiting approval stores exactly one signed
envelope and staging required for commit. Committing reserves the settlement
nonce before publishing anything. Run, vault segment, policy values,
provenance, task state, and agent claim become visible in one commit or none.

Vault:

```text
PendingIngress
  → Live
  → ReleaseAuthorized
  → DispatchPrepared
  → Dispatching
  → Released

terminal:
Revoked | Expired | Indeterminate | RestartInvalidated
```

Every operation uses the same liveness predicate over object type, boot,
client/service, peer, run, active state manifest, wall-clock floor, monotonic
expiry, revocation, and consumption.

Invalid input or settlement changes no live state. After dispatch preparation,
approval, ticket, quota, vault segment, token set, destination, and one nonce
are bound permanently. They are never reassigned to another nonce.

## 13. Durable dispatch and result recovery

### 13.1 kerneld WAL

The semantic authorization objects reused without translation across intent,
approval, dispatch, WAL, and executor verification are:

```rust
struct ToolExecutionSemanticBindingV2 {
    plan_revision_digest: PlanRevisionDigestV2,
    internal_step_id: InternalStepIdV2,
    tool_descriptor_digest: Digest32,
    argument_digest: Digest32,
    provenance_set_digest: Digest32,
    token_set_digest: Digest32,
    destination_digest: Digest32,
    display_projection_digest: Digest32,
    display_digest: Digest32,
    executor_identity_digest: Digest32,
    attempt_kind: AttemptKindV2,
}

struct FinalReleaseSemanticBindingV2 {
    durable_release_id: DurableReleaseIdV2,
    vault_segment_internal_id: Digest32,
    vault_segment_digest: Digest32,
    release_payload_digest: Digest32,
    evidence_digest: Digest32,
    token_set_digest: Digest32,
    destination_digest: Digest32,
    display_projection_digest: Digest32,
    display_digest: Digest32,
    executor_identity_digest: Digest32,
    release_quota_subject_digest: Digest32,
}

enum DispatchSubjectV2 {
    ToolExecution {
        action_intent_id: ActionIntentIdV2,
        binding: ToolExecutionSemanticBindingV2,
        approval_settlement_digest: Option<Digest32>,
    } = 1,
    FinalRelease {
        binding: FinalReleaseSemanticBindingV2,
        approval_settlement_digest: Digest32,
    } = 2,
}

struct DispatchCoreV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    execution_nonce: Nonce32,
    subject: DispatchSubjectV2,
    dispatch_subject_digest: Digest32,
    executor_identity: ExecutorIdentityV2,
    executor_key_id: HpkeX25519KeyIdV2,
    executor_connector_registry_digest: Digest32,
    expires_at: UnixMillis,
}
```

```text
ToolExecutionSemanticBindingDigest =
  SHA-256("SAVANA_TOOL_EXECUTION_SEMANTIC_BINDING_V2\0" ||
          canonical_cbor(ToolExecutionSemanticBindingV2))

FinalReleaseSemanticBindingDigest =
  SHA-256("SAVANA_FINAL_RELEASE_SEMANTIC_BINDING_V2\0" ||
          canonical_cbor(FinalReleaseSemanticBindingV2))

DispatchSubjectDigest =
  SHA-256("SAVANA_DISPATCH_SUBJECT_V2\0" ||
          canonical_cbor(DispatchSubjectV2))

DispatchCoreDigest =
  SHA-256("SAVANA_DISPATCH_CORE_V2\0" ||
          canonical_cbor(DispatchCoreV2))
```

`DispatchCoreV2` contains no HPKE ciphertext, encapsulated key, outer
signature, or self-digest, so its digest is non-circular.
`dispatch_subject_digest` must equal the digest of the embedded closed
`subject`. `ToolExecution` is the only subject that can contain an
`ActionIntentIdV2`; `FinalRelease` contains its typed durable release identity
and never manufactures an action-intent ID. The full executor identity must
hash to the subject binding's `executor_identity_digest`. The encrypted
execution payload carries the exact subject-specific material and second
copies of both core and subject digests; execd requires every duplicate to
match.

kerneld then persists branch-typed outcomes:

```rust
enum DurableQuarantineEvidenceV2 {
    ToolResult {
        result_digest: Digest32,
        effect_started_receipt_digest: Digest32,
    } = 1,
    FinalRelease {
        durable_release_id: DurableReleaseIdV2,
        final_release_receipt_digest: Digest32,
        release_audit_digest: Digest32,
        effect_started_receipt_digest: Digest32,
    } = 2,
}

enum DurablePublicOutcomeV2 {
    ToolExecutionSucceeded {
        result_digest: Digest32,
        document_internal_digest: Digest32,
    } = 1,
    FinalReleaseSucceeded {
        durable_release_id: DurableReleaseIdV2,
        final_release_receipt_digest: Digest32,
        release_audit_digest: Digest32,
    } = 2,
    EffectSucceededOutputQuarantined {
        evidence: DurableQuarantineEvidenceV2,
        class: PublicFailureClassV2,
    } = 3,
    FailedNoEffect {
        class: PublicFailureClassV2,
    } = 4,
    Indeterminate = 5,
}

enum KernelTransportWriteStateV2 {
    NotStarted = 1,
    WriteMayHaveOccurred = 2,
    ConfirmedZeroBytes = 3,
    CompleteFrame = 4,
}

struct KernelDispatchJournalEntryV2 {
    schema_version: u16,
    journal_sequence: u64,
    previous_record_digest: Digest32,
    active_state_manifest_sequence: u64,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    originating_boot_id: BootIdV2,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    execution_nonce: Nonce32,
    subject: DispatchSubjectV2,
    dispatch_subject_digest: Digest32,
    executor_identity: ExecutorIdentityV2,
    dispatch_core_digest: Digest32,
    sealed_envelope_digest: Digest32,
    sealed_envelope_bytes: BoundedBytesV2<8_MiB>,
    transport_frame_digest: Digest32,
    transport_write_state: KernelTransportWriteStateV2,
    confirmed_bytes_written: u32,
    state: KernelDispatchStateV2,
    effect_started_receipt:
        Option<SignedExecutorEffectStartedReceiptV2>,
    effect_started_receipt_digest: Option<Digest32>,
    final_release_receipt:
        Option<SignedExecutorFinalReleaseReceiptV2>,
    final_release_audit_evidence:
        Option<ExecutorFinalReleaseAuditEvidenceV2>,
    completion: Option<ExecutorCompletionDescriptorV2>,
    public_outcome: Option<DurablePublicOutcomeV2>,
    created_at: UnixMillis,
    expires_at: UnixMillis,
    record_digest: Digest32,
}

enum KernelDispatchStateV2 {
    Prepared = 1,
    Sending = 2,
    Accepted = 3,
    CompletionAvailable = 4,
    CompletionCommitPending = 5,
    CompletionCommitted = 6,
    EffectSucceededOutputQuarantined = 7,
    Acknowledged = 8,
    FailedNoEffect = 9,
    Indeterminate = 10,
}
```

`record_digest` is
`SHA-256("SAVANA_KERNEL_DISPATCH_WAL_RECORD_V2\0" ||
canonical_cbor(entry excluding record_digest))`. The WAL contains no plaintext
argument, destination, settlement, result, release payload, or vault entry. It
stores the exact closed subject, its digest, and the HPKE-sealed executor
envelope required to resend the same nonce. The WAL subject must be
byte-identical to the core subject and the immutable intent or release record;
reconstructing a look-alike binding is forbidden.

The two effect-start receipt options are always both `None` or both `Some`;
when `Some`, the digest is
`SignedExecutorEffectStartedReceiptDigest` of the exact stored signed object.
Before any quota transition predicated on an execd effect-start receipt, and
before any known-success, quarantine, or public-outcome write, kerneld verifies
the execd role key/domain and commits those full signed bytes to this WAL. On
an `ExecutorStatusV2::Indeterminate` with both receipt options `Some`, that
verification and WAL persistence commit before the terminal state and
`Spent`/`IndeterminateSpent` quota transition. Both options may remain `None`
only for an authenticated terminal uncertainty with no execd `EffectStarted`
or other known-effect lineage; section 11.3's
`Reserved → IndeterminateSpent` transition then claims uncertainty, not a
receipt or known effect. For a final-release `CompletionAvailable` or later
known-effect state, `final_release_receipt` and
`final_release_audit_evidence` are both `Some`, their recomputed digests equal
the exact completion descriptor, and their subject/material fields match this
record. They are both `None` for every tool subject. A public
`FinalReleaseSucceeded` or final-release quarantine without all four durable
objects—the effect receipt, final receipt, audit evidence, and typed
completion—is corruption. An `Indeterminate` with no execd known-effect
lineage may retain both effect-receipt options as `None`, but it cannot claim
effect absence, release quota, or produce known-success evidence. Once
kerneld or execd has an effect-start or other known-effect lineage, a
receipt-free projection is corruption.

```rust
struct KernelZeroByteSendProofV2 {
    installation_id: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    transport_frame_digest: Digest32,
    wal_record_digest: Digest32,
    transport_write_state: KernelTransportWriteStateV2,
    confirmed_bytes_written: u32,       // exactly 0
    transport_audit_digest: Digest32,
}
```

Before the first OS write call, kerneld appends and fsyncs
`WriteMayHaveOccurred`; therefore a crash around that call can never look like
zero bytes. `ConfirmedZeroBytes` may be appended only after the transport
implementation returns an audited definitive zero-byte result and closes the
connection. `NotStarted` is proof only while no write call has been entered.
The zero-byte proof is valid only for one of those two states with count zero
and exact frame/core/WAL/audit digests. Any partial positive count, missing
post-call record, crash from `WriteMayHaveOccurred`, or accounting ambiguity
forbids resend.

Order:

1. create the one nonce and sealed dispatch;
2. write/fsync `Prepared`;
3. write/confirm pre-effect audit;
4. append/fsync `WriteMayHaveOccurred`, then make the OS write and append its
   exact confirmed outcome;
5. record accepted or uncertain state;
6. query status, then fetch and verify the exact zeroizing completion through
   operation 63;
7. run the subject-specific completion gate: result vault/value/provenance for
   a tool, or final-release receipt/audit/vault transition for a release;
8. write/fsync `CompletionCommitted`;
9. send operation 62;
10. write/fsync `Acknowledged`.

Commit-uncertain journal state prevents new dispatch until recovery.

### 13.2 execd journal

```rust
enum ConnectorCodecJobModeV2 {
    PrepareAndDecode = 1,
    DecodeRetainedResponse = 2,
}

struct ConnectorCodecStableBindingV2 {
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    connector_identity_digest: Digest32,
    connector_codec_artifact_digest: Digest32,
    credential_handle_identity_digest: Digest32,
    bounded_material_digest: Digest32,
    idempotency_contract: ExecutorIdempotencyContractV2,
    connector_retry_policy_digest: Digest32,
    no_network_sandbox_profile_digest: Digest32,
    credential_absence_profile_digest: Digest32,
}

struct UnsignedConnectorCodecJobDescriptorV2 {
    schema_version: u16,                 // exactly 2
    stable_binding: ConnectorCodecStableBindingV2,
    stable_binding_digest: Digest32,
    mode: ConnectorCodecJobModeV2,
    external_attempt_ordinal: u16,
    codec_job_ordinal: u16,
    worker_job_nonce: Nonce32,
    prepared_request_digest: Option<Digest32>,
    retained_provider_response_digest: Option<Digest32>,
    retained_provider_response_length: Option<u32>,
    effect_started_receipt_digest: Option<Digest32>,
    anonymous_channel_binding_digest: Digest32,
    ephemeral_attestation_public_key: FixedBytesV2<32>,
    ephemeral_attestation_key_id: Ed25519KeyIdV2,
    deadline: UnixMillis,
}

enum ConnectorCodecJobInputV2 {
    Prepare {
        credential_free_material: ZeroizingBytesV2,
        material_digest: Digest32,
    } = 1,
    DecodeRetainedResponse {
        retained_provider_response: ZeroizingBytesV2,
        provider_response_digest: Digest32,
        effect_started_receipt:
            SignedExecutorEffectStartedReceiptV2,
    } = 2,
}

struct PreparedProviderRequestV2 {
    credential_free_request: ZeroizingBytesV2,
    credential_free_request_digest: Digest32,
    credential_insertion_plan_digest: Digest32,
    provider_endpoint_binding_digest: Digest32,
    provider_idempotency_binding_digest: Digest32,
    maximum_response_bytes: u32,
}

struct UnsignedConnectorCodecPreparedRequestAttestationV2 {
    schema_version: u16,                 // exactly 2
    connector_codec_job_descriptor_digest: Digest32,
    stable_binding_digest: Digest32,
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    external_attempt_ordinal: u16,
    codec_job_ordinal: u16,
    worker_job_nonce: Nonce32,
    ephemeral_attestation_key_id: Ed25519KeyIdV2,
    prepared_provider_request_digest: Digest32,
    credential_free_request_digest: Digest32,
    credential_insertion_plan_digest: Digest32,
    ordered_codec_transcript_digest: Digest32,
    completed_at: UnixMillis,
}

enum ConnectorCodecDecodedCompletionV2 {
    ToolResult {
        result_digest: Digest32,
        encoded_length: u32,
    } = 1,
    FinalReleaseEvidence {
        durable_release_id: DurableReleaseIdV2,
        provider_evidence_digest: Digest32,
        provider_evidence_length: u32,
        provider_success_discriminant_digest: Digest32,
    } = 2,
}

enum ConnectorCodecOutcomePayloadV2 {
    ToolResult {
        result: ZeroizingBytesV2,
    } = 1,
    FinalReleaseEvidence {
        provider_evidence: ZeroizingBytesV2,
        provider_success_discriminant_digest: Digest32,
    } = 2,
}

enum ConnectorCodecOutcomeV2 {
    Completion {
        decoded_completion: ConnectorCodecDecodedCompletionV2,
        outcome_payload_digest: Digest32,
    } = 1,
    FailedBeforeEffect {
        class: ExecutorFailureClassV2,
        failure_evidence_digest: Digest32,
    } = 2,
    Indeterminate {
        observation_digest: Digest32,
    } = 3,
}

struct UnsignedConnectorCodecOutcomeAttestationV2 {
    schema_version: u16,                 // exactly 2
    connector_codec_job_descriptor_digest: Digest32,
    stable_binding_digest: Digest32,
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    external_attempt_ordinal: u16,
    codec_job_ordinal: u16,
    worker_job_nonce: Nonce32,
    ephemeral_attestation_key_id: Ed25519KeyIdV2,
    prepared_provider_request_digest: Option<Digest32>,
    effect_started_receipt_digest: Option<Digest32>,
    provider_response_digest: Option<Digest32>,
    provider_response_length: Option<u32>,
    outcome: ConnectorCodecOutcomeV2,
    ordered_codec_transcript_digest: Digest32,
    completed_at: UnixMillis,
}

enum ConnectorCodecPipeFrameV2 {
    Job {
        descriptor: SignedConnectorCodecJobDescriptorV2,
        input: ConnectorCodecJobInputV2,
    } = 1,
    PreparedRequest {
        request: PreparedProviderRequestV2,
        attestation:
            SignedConnectorCodecPreparedRequestAttestationV2,
    } = 2,
    ProviderResponse {
        response: ZeroizingBytesV2,
        response_digest: Digest32,
        effect_started_receipt:
            SignedExecutorEffectStartedReceiptV2,
    } = 3,
    Outcome {
        payload: Option<ConnectorCodecOutcomePayloadV2>,
        attestation: SignedConnectorCodecOutcomeAttestationV2,
    } = 4,
}

enum ConnectorCodecAttemptStateV2 {
    WorkerReserved = 1,
    PreparedRequestValidated = 2,
    EffectStartedFsynced = 3,
    ProviderResponseRetained = 4,
    CompletionDecoded = 5,
    FailedBeforeEffect = 6,
    Indeterminate = 7,
}

struct ConnectorCodecAttemptRecordV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    stable_binding_digest: Digest32,
    external_attempt_ordinal: u16,
    codec_job_ordinal: u16,
    worker_job_nonce: Nonce32,
    connector_codec_job_descriptor_digest: Digest32,
    state: ConnectorCodecAttemptStateV2,
    prepared_provider_request_digest: Option<Digest32>,
    effect_started_receipt_digest: Option<Digest32>,
    retained_provider_response_digest: Option<Digest32>,
    connector_codec_outcome_attestation_digest: Option<Digest32>,
    previous_attempt_record_digest: Option<Digest32>,
    created_at: UnixMillis,
    record_digest: Digest32,
}

struct ExecutorEffectStartedReceiptRecordV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    external_attempt_ordinal: u16,
    signed_receipt: SignedExecutorEffectStartedReceiptV2,
    signed_receipt_digest: Digest32,
    created_at: UnixMillis,
    retain_until: UnixMillis,
    record_digest: Digest32,
}

struct ExecutorFinalReleaseAuditEvidenceV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    durable_release_id: DurableReleaseIdV2,
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    vault_segment_digest: Digest32,
    release_payload_digest: Digest32,
    destination_digest: Digest32,
    executor_identity_digest: Digest32,
    connector_identity_digest: Digest32,
    external_attempt_ordinal: u16,
    connector_codec_attempt_record_digest: Digest32,
    connector_codec_job_descriptor_digest: Digest32,
    prepared_provider_request_digest: Digest32,
    effect_started_receipt_digest: Digest32,
    provider_response_digest: Digest32,
    provider_response_length: u32,
    connector_codec_outcome_attestation_digest: Digest32,
    provider_evidence_digest: Digest32,
    provider_evidence_length: u32,
    provider_success_discriminant_digest: Digest32,
    created_at: UnixMillis,
}

struct ExecutorJournalRecordV2 {
    schema_version: u16,                 // exactly 2
    journal_sequence: u64,
    previous_record_digest: Digest32,
    record_id: Digest32,
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    sealed_envelope_digest: Digest32,
    executor_identity: ExecutorIdentityV2,
    executor_key_id: HpkeX25519KeyIdV2,
    connector_identity_digest: Digest32,
    state: ExecutorJournalStateV2,
    latest_connector_codec_attempt_record_digest: Option<Digest32>,
    encrypted_execution_record_id: Option<Digest32>,
    effect_started_receipt_digest: Option<Digest32>,
    encrypted_effect_started_receipt_record_id: Option<Digest32>,
    retained_provider_response_digest: Option<Digest32>,
    encrypted_provider_response_record_id: Option<Digest32>,
    final_release_audit_evidence_digest: Option<Digest32>,
    encrypted_release_evidence_record_id: Option<Digest32>,
    completion: Option<ExecutorCompletionDescriptorV2>,
    encrypted_completion_record_id: Option<Digest32>,
    kernel_commit_digest: Option<Digest32>,
    created_at: UnixMillis,
    expires_at: UnixMillis,
    record_digest: Digest32,
}

enum ExecutorJournalStateV2 {
    Prepared = 1,
    EffectStarted = 2,
    CompletionAvailable = 3,
    FailedNoEffect = 4,
    Indeterminate = 5,
    Acknowledged = 6,
    ProviderAttemptPrepared = 7,
    ReleaseEvidencePrepared = 8,
    ProviderRetryPrepared = 9,
    ProviderResponseRetained = 10,
}

struct ExecutorNonceTombstoneV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    terminal_state: ExecutorJournalStateV2,
    completion: Option<ExecutorCompletionDescriptorV2>,
    final_journal_record_digest: Digest32,
    retain_until: UnixMillis,
    tombstone_digest: Digest32,
}
```

```text
ExecutorJournalRecordDigest =
  SHA-256("SAVANA_EXECD_JOURNAL_RECORD_V2\0" ||
          canonical_cbor(record excluding record_digest))
```

`tombstone_digest` is
`SHA-256("SAVANA_EXECD_NONCE_TOMBSTONE_V2\0" ||
canonical_cbor(tombstone excluding tombstone_digest))`.
`terminal_state` is restricted to `FailedNoEffect`, `Indeterminate`, or
`Acknowledged`. A `FailedNoEffect` tombstone is legal only when the complete
record chain contains no `EffectStarted`; any chain containing
`EffectStarted`, `ProviderRetryPrepared`, `ProviderResponseRetained`, or
`ReleaseEvidencePrepared` can terminalize only as `Indeterminate` or
`Acknowledged` with the exact retained receipt/evidence lineage.

The `(execution_nonce → dispatch_core_digest, dispatch_subject_digest, state,
latest_record_digest)` index is durably updated in the same transaction as
each journal append.
Before publishing `Prepared`, execd re-encrypts the validated
`SealedExecutionPlaintextV2` under its at-rest journal epoch and atomically
stores the resulting record ID in `encrypted_execution_record_id`. That field
is `Some` in every nonterminal `Prepared`, `ProviderAttemptPrepared`,
`ProviderRetryPrepared`, `EffectStarted`, `ProviderResponseRetained`,
`ReleaseEvidencePrepared`, and `CompletionAvailable` record.
It remains recoverable until a terminal tombstone no longer permits connector
or completion work.

The nonterminal option matrix is exact:

| State/subject | latest attempt | effect receipt digest + encrypted signed record | response digest + encrypted response | final-release audit digest + encrypted evidence | completion + encrypted completion | kernel commit |
|---|---:|---:|---:|---:|---:|---:|
| `Prepared` | `None` | `None/None` | `None/None` | `None/None` | `None/None` | `None` |
| `ProviderAttemptPrepared` | `Some` | `None/None` | `None/None` | `None/None` | `None/None` | `None` |
| `ProviderRetryPrepared` | `Some` | `Some/Some(prior attempt)` | `None/None` | `None/None` | `None/None` | `None` |
| `EffectStarted` | `Some` | `Some/Some` | `None/None` | `None/None` | `None/None` | `None` |
| `ProviderResponseRetained` | `Some` | `Some/Some` | `Some/Some` | `None/None` | `None/None` | `None` |
| `ReleaseEvidencePrepared` / final release | `Some` | `Some/Some` | `Some/Some` | `Some/Some` | `None/None` | `None` |
| `CompletionAvailable` / tool | `Some` | `Some/Some` | `Some/Some` | `None/None` | `Some/Some(ToolResult)` | `None` |
| `CompletionAvailable` / final release | `Some` | `Some/Some` | `Some/Some` | `Some/Some` | `Some/Some(FinalReleaseReceipt)` | `None` |

`ReleaseEvidencePrepared` is illegal for a tool subject. Its audit digest is
the exact `ExecutorFinalReleaseAuditEvidenceDigest`, and its encrypted
evidence record contains the byte-exact provider evidence and matching
one-job outcome attestation, not a signed execd receipt. A
`CompletionAvailable` final-release record must name that predecessor through
the signed final-release receipt and repeat the same audit/evidence digests.
`ProviderAttemptPrepared` is legal only for external attempt ordinal one when
the execution chain has no `EffectStarted` ancestor. `ProviderRetryPrepared`
is legal only for an ordinal greater than one, a
`ConnectorCodecStableBindingV2.idempotency_contract` equal to
`ConnectorIdempotentByExecutionNonce`, an exact bounded retry policy that
still permits that ordinal, and a chain with a prior
`EffectStarted` receipt; its `effect_started_receipt_digest` is that prior
receipt and therefore cannot be projected as no effect. If the new attempt
record has ordinal `n`, the retained signed receipt and its authenticated
`EffectStarted` ancestor have ordinal exactly `n-1`; a gap, older receipt,
different descriptor, or cross-chain substitute is corruption. It may
advance only to the matching new `EffectStarted` record or to
`Indeterminate`, never `FailedNoEffect` or quota release.
`ProviderResponseRetained` contains the exact encrypted response and receipt
for the current attempt before any decode/recovery worker sees those bytes;
their ordinals/descriptors equal the latest attempt record. It may advance
only to a typed completion, `ReleaseEvidencePrepared`, or `Indeterminate`.
`encrypted_completion_record_id` is `Some` only for
`CompletionAvailable`; its decrypted descriptor and payload must match the
journal's `completion`. `FailedNoEffect` has no receipt, retained response,
audit, completion, or kernel commit; `Indeterminate` has no completion/kernel
commit, retains the effect-receipt pair whenever its chain has effect or
known-effect ancestry, and retains whichever authenticated response or
release-evidence pair was durably reached. With no such ancestry its two
effect-receipt fields are both `None`. `Acknowledged` retains the exact
completion, evidence digests, receipt digest, and kernel commit but has no
encrypted execution/effect-receipt/response/evidence/completion record ID
after the
acknowledged deletion transaction. Every other option combination is
corruption and fails stop.

A restart may continue only from those exact encrypted records. Missing,
undecryptable, digest-mismatched, or wrong-epoch material becomes
`Indeterminate` and never starts a codec job or provider transport. If the
record chain has effect or known-effect ancestry, loss of its sealed full
receipt additionally fails stop for status projection: execd cannot encode
that `Indeterminate` with both receipt options `None`.
Nonce tombstones retain the nonce, core digest, subject digest, terminal
state, and final record digest until the maximum
action/release/replay/recovery retention deadline.
GC never turns a previously seen nonce into absence.

The codec ABI has the following exact digests and signature inputs:

```text
ConnectorCodecStableBindingDigest =
  SHA-256("SAVANA_CONNECTOR_CODEC_STABLE_BINDING_V2\0" ||
          canonical_cbor(ConnectorCodecStableBindingV2))

ConnectorCodecJobDescriptorDigest =
  SHA-256("SAVANA_CONNECTOR_CODEC_JOB_DESCRIPTOR_V2\0" ||
          exact_unsigned_job_descriptor_payload_bstr)

ConnectorCodecJobDescriptorSignature =
  Ed25519.sign(
    execd_connector_codec_job_descriptor_key,
    "SAVANA_CONNECTOR_CODEC_JOB_DESCRIPTOR_SIGNATURE_V2\0" ||
    SHA-256(exact_unsigned_job_descriptor_payload_bstr))

PreparedProviderRequestDigest =
  SHA-256("SAVANA_PREPARED_PROVIDER_REQUEST_V2\0" ||
          canonical_cbor(PreparedProviderRequestV2))

ConnectorCodecOutcomePayloadDigest =
  SHA-256("SAVANA_CONNECTOR_CODEC_OUTCOME_PAYLOAD_V2\0" ||
          canonical_cbor(ConnectorCodecOutcomePayloadV2))

ConnectorProviderResponseDigest =
  SHA-256("SAVANA_CONNECTOR_PROVIDER_RESPONSE_V2\0" ||
          exact_provider_response_bytes)

ConnectorProviderEvidenceDigest =
  SHA-256("SAVANA_CONNECTOR_PROVIDER_EVIDENCE_V2\0" ||
          exact_provider_evidence_bytes)

ConnectorCodecPreparedRequestSignature =
  Ed25519.sign(
    exact_job_ephemeral_attestation_key,
    "SAVANA_CONNECTOR_CODEC_PREPARED_REQUEST_SIGNATURE_V2\0" ||
    SHA-256(exact_unsigned_prepared_attestation_payload_bstr))

ConnectorCodecOutcomeSignature =
  Ed25519.sign(
    exact_job_ephemeral_attestation_key,
    "SAVANA_CONNECTOR_CODEC_OUTCOME_SIGNATURE_V2\0" ||
    SHA-256(exact_unsigned_outcome_attestation_payload_bstr))

SignedConnectorCodecOutcomeAttestationDigest =
  SHA-256("SAVANA_CONNECTOR_CODEC_OUTCOME_ATTESTATION_V2\0" ||
          exact_signed_outcome_attestation_object_bytes)

ConnectorCodecTranscriptStep[0] =
  SHA-256("SAVANA_CONNECTOR_CODEC_TRANSCRIPT_BEGIN_V2\0" ||
          ConnectorCodecJobDescriptorDigest)

ConnectorCodecTranscriptStep[n + 1] =
  SHA-256("SAVANA_CONNECTOR_CODEC_TRANSCRIPT_STEP_V2\0" ||
          ConnectorCodecTranscriptStep[n] ||
          direction_tag_u16be || frame_tag_u16be ||
          frame_ordinal_u32be || SHA-256(canonical_frame_without_attestation))

ConnectorCodecAttemptRecordDigest =
  SHA-256("SAVANA_CONNECTOR_CODEC_ATTEMPT_RECORD_V2\0" ||
          canonical_cbor(ConnectorCodecAttemptRecordV2
                         excluding record_digest))

SignedExecutorEffectStartedReceiptDigest =
  SHA-256("SAVANA_EXECD_EFFECT_STARTED_SIGNED_RECEIPT_V2\0" ||
          exact_signed_object_bytes)

ExecutorEffectStartedReceiptRecordDigest =
  SHA-256("SAVANA_EXECD_EFFECT_STARTED_RECEIPT_RECORD_V2\0" ||
          canonical_cbor(ExecutorEffectStartedReceiptRecordV2
                         excluding record_digest))

SignedExecutorFinalReleaseReceiptDigest =
  SHA-256("SAVANA_EXECD_FINAL_RELEASE_SIGNED_RECEIPT_V2\0" ||
          exact_signed_object_bytes)

ExecutorFinalReleaseAuditEvidenceDigest =
  SHA-256("SAVANA_EXECD_FINAL_RELEASE_AUDIT_EVIDENCE_V2\0" ||
          canonical_cbor(ExecutorFinalReleaseAuditEvidenceV2))
```

Each `exact_signed_object_bytes` above is the canonical section 3.1 signed
object of the formula's named receipt type. An
`ExecutorEffectStartedReceiptRecordV2` repeats the installation,
manifest/generation/fence, nonce, core, subject, and attempt ordinal from its
signed payload; `created_at` equals the signed `started_at`,
`signed_receipt_digest` equals
`SignedExecutorEffectStartedReceiptDigest`, and `retain_until` covers the
maximum executor/kernel/quota/recovery retention. It is encrypted as a
`SealedJournalRecordV2`; the journal's
`encrypted_effect_started_receipt_record_id` resolves exactly that sealed
record. A mismatch, missing record, or early deletion is `Indeterminate`, not
a digest-only proof.
Every `provider_response_digest`, `provider_evidence_digest`, and
`connector_codec_outcome_attestation_digest` in this section equals,
respectively, `ConnectorProviderResponseDigest`,
`ConnectorProviderEvidenceDigest`, and
`SignedConnectorCodecOutcomeAttestationDigest`; raw SHA-256, an unsigned
attestation payload, or a digest under any other domain is rejected.

The job-mode matrix is closed:

| Mode | descriptor prepared/response/length/effect fields | one legal job input | legal first worker output |
|---|---|---|---|
| `PrepareAndDecode` | all four `None` | `Prepare`, whose material digest equals the stable binding | `PreparedRequest`, or `Outcome(FailedBeforeEffect)` |
| `DecodeRetainedResponse` | all four `Some` and mutually matching the retained journal objects | `DecodeRetainedResponse` with the same response and receipt | `Outcome(Completion or Indeterminate)` |

In `PrepareAndDecode`, after `PreparedRequest` has been verified, execd may
send exactly one `ProviderResponse` on that same anonymous channel; only then
may the worker return `Outcome(Completion or Indeterminate)`.
`FailedBeforeEffect` requires `payload=None` and every effect/response field
in the attestation to be `None`. `Completion` requires
`payload=Some`, the exact signed effect-started receipt and exact retained
provider-response digest/length, and an `outcome_payload_digest` equal to the
exact `ConnectorCodecOutcomePayloadDigest`. A tool subject requires
`ConnectorCodecDecodedCompletionV2::ToolResult` plus
`ConnectorCodecOutcomePayloadV2::ToolResult` with matching result digest and
length. A final-release subject requires
`ConnectorCodecDecodedCompletionV2::FinalReleaseEvidence` plus
`ConnectorCodecOutcomePayloadV2::FinalReleaseEvidence` with the same durable
release, provider-evidence digest/length, and success-discriminant digest.
The worker ABI cannot contain `ExecutorCompletionDescriptorV2`,
`ExecutorCompletionPayloadV2`, `SignedExecutorFinalReleaseReceiptV2`, or an
execd service-key signature; execd constructs those only after the
ephemeral-attested evidence has passed the durable two-stage flow below.
`Indeterminate` requires a signed
effect-started receipt, has `payload=None`, and can never be relabeled
failed-before-effect. Every other mode/frame/option/subject combination is
noncanonical.

Execd signs the job descriptor only after its private launcher has created
one anonymous socketpair/pipe, verified the deployment-pinned codec artifact,
installed the exact no-network sandbox, and removed every credential,
keystore, network, listener, filesystem-secret, and unrelated inherited
descriptor from the child. The worker receives only its one codec channel.
It cannot `connect`, `bind`, `listen`, resolve a provider, open a credential
store, inherit a connector credential, or emit an external byte. The
descriptor exposes only a non-resolving
`credential_handle_identity_digest`; the handle and secret remain in execd.
The ephemeral Ed25519 private key is generated for that one worker job,
exists only in the sandboxed worker, is zeroized on exit, and is never stored
as a service key. A descriptor, ephemeral key, frame, or attestation from a
different job, channel, worker artifact, execution nonce, attempt ordinal, or
codec transcript is rejected.

The worker's `PreparedProviderRequestV2` is credential-free codec output.
Execd verifies its signature, transcript, stable binding, endpoint binding,
idempotency binding, byte/response ceilings, and compiled credential
insertion-plan digest. Only execd's main process resolves the exact internal
credential handle and constructs the final authenticated provider transport.
Before the first provider byte of each external attempt, execd first appends
and fsyncs `ProviderAttemptPrepared` for ordinal one or
`ProviderRetryPrepared` for a legal later ordinal. Both contain the exact
current attempt-record, descriptor, and prepared-request commitment but no
receipt for the new attempt; the retry state additionally retains the prior
effect-started receipt. Execd then signs
`SignedExecutorEffectStartedReceiptV2` over that predecessor journal digest,
persists the complete signed bytes in one encrypted
`ExecutorEffectStartedReceiptRecordV2`, appends and fsyncs a later
`EffectStarted` record that contains both the receipt digest and that sealed
record ID, and only then may its main transport emit the first provider byte.
The predecessor cannot contain the receipt digest and the receipt cannot bind
the later `EffectStarted` record, so the construction is a directed hash DAG.
No worker frame can substitute for either durable record or the receipt.
Execd retains the exact bounded provider response encrypted and appends/fsyncs
`ProviderResponseRetained` before giving it to the same codec or a recovery
codec; completion publication verifies that head's response digest, codec
outcome attestation, typed payload, and full transcript.

For a final-release completion, execd verifies the
`FinalReleaseEvidence` payload against the exact release subject and then
constructs one `ExecutorFinalReleaseAuditEvidenceV2` from the immutable
subject/material, current attempt, prepared request, effect-start receipt,
retained response, ephemeral outcome attestation, provider evidence, and
manifest-pinned success discriminant. In one transaction it encrypts and
stores the byte-exact evidence plus attestation and appends/fsyncs
`ReleaseEvidencePrepared` containing their record ID and the exact audit
digest; that record contains no final-release receipt or receipt digest.
Only afterward may the execd main process use its active effect-receipt key to
sign `SignedExecutorFinalReleaseReceiptV2`. A following transaction stores
the exact `ExecutorCompletionPayloadV2::FinalReleaseReceipt` and appends
`CompletionAvailable` naming its descriptor and encrypted record. A crash at
any boundary resumes from the directed predecessor; it never asks a codec
worker to sign with a service key, reconstructs an audit object from
unauthenticated bytes, or creates a second provider attempt merely to finish
receipt signing.

`ConnectorCodecAttemptRecordV2` is an append-only per-execution chain.
`external_attempt_ordinal` begins at one and increases by exactly one only
for another provider transport attempt. A codec recovery over an already
retained response keeps that external ordinal, increments
`codec_job_ordinal`, uses mode `DecodeRetainedResponse`, and creates a new job
nonce, anonymous channel, and ephemeral key; it sends no provider byte.
A provider-idempotent retry likewise starts a fresh one-shot worker and
descriptor, but the stable binding, execution nonce, core, subject, bounded
material, connector/codec artifact, credential-handle identity, sandbox
profiles, and retry contract must be byte-identical. Relative to the prior
descriptor, only the compiled per-attempt/per-job fields—mode as required,
strict ordinals, job nonce, channel binding, fresh ephemeral key, retained
response option fields, receipt binding, and bounded deadline—may change.
The execd journal reserves that new attempt record before the worker starts.

`ConnectorNonIdempotentSingleAttempt` permits only external attempt ordinal
one and never starts a second provider attempt. For
`ConnectorIdempotentByExecutionNonce`, a second provider attempt is legal
only while the immutable compiled `BoundedConnectorRetryPolicyV2` permits the
next ordinal and total elapsed time; it reuses the exact execution nonce and
provider idempotency binding. Codec re-execution over the same original or
retained bytes is not an external retry. Reusing an old job descriptor on a
new worker, changing any stable field, skipping an ordinal, exceeding either
bound, or starting a second non-idempotent worker fails stop without an
external byte.

```rust
struct UnsignedCompleteNonceAbsenceProofV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    nonce_index_generation: u64,
    retained_genesis_or_checkpoint_digest: Digest32,
    current_journal_head_digest: Digest32,
    complete_index_digest: Digest32,
    issued_at: UnixMillis,
}

struct UnsignedExecutorEffectStartedReceiptV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    executor_identity_digest: Digest32,
    connector_identity_digest: Digest32,
    external_attempt_ordinal: u16,
    connector_codec_job_descriptor_digest: Digest32,
    prepared_provider_request_digest: Digest32,
    provider_attempt_prepared_journal_record_digest: Digest32,
    started_at: UnixMillis,
}

struct UnsignedExecutorFinalReleaseReceiptV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    durable_release_id: DurableReleaseIdV2,
    execution_nonce: Nonce32,
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    vault_segment_digest: Digest32,
    release_payload_digest: Digest32,
    destination_digest: Digest32,
    executor_identity_digest: Digest32,
    provider_evidence_digest: Digest32,
    release_audit_digest: Digest32,
    release_evidence_prepared_journal_record_digest: Digest32,
    completed_at: UnixMillis,
}
```

`CompleteNonceAbsenceProofV2` is the signed-object encoding of that payload
under the execd identity key with signature input
`"SAVANA_EXECD_NONCE_ABSENCE_V2\0" ||
SHA-256(payload_bstr)`. execd may sign it only after a successful full
journal/index verification under the dispatch and nonce-index lock.
`SignedExecutorEffectStartedReceiptV2` uses the same signed-object encoding
under the distinct active execd effect-receipt key with signature input
`"SAVANA_EXECD_EFFECT_STARTED_RECEIPT_V2\0" ||
SHA-256(payload_bstr)`. Its
`provider_attempt_prepared_journal_record_digest` names the already fsynced
receipt-free `ProviderAttemptPrepared` or `ProviderRetryPrepared`
predecessor. The later `EffectStarted` record names the signed
receipt digest and encrypted signed-receipt record ID; that later record and
the complete signed-receipt record are both fsynced before execd's main
transport crosses the first possible external-byte boundary.
Neither object hashes the other. The receipt digest binds the exact closed
dispatch subject; a tool receipt cannot settle a release, and a release
receipt cannot settle a tool action.
`SignedExecutorFinalReleaseReceiptV2` uses the same signed-object encoding and
active execd effect-receipt key but the disjoint signature input
`"SAVANA_EXECD_FINAL_RELEASE_RECEIPT_V2\0" ||
SHA-256(payload_bstr)`. It is legal only for
`DispatchSubjectV2::FinalRelease`, and all release/vault/payload/destination/
executor fields must equal the subject and sealed material. Its
descriptor/payload `final_release_receipt_digest` equals the exact
`SignedExecutorFinalReleaseReceiptDigest`. Its
`release_audit_digest` equals the exact
`ExecutorFinalReleaseAuditEvidenceDigest`; its
`release_evidence_prepared_journal_record_digest` names the already fsynced
receipt-free `ReleaseEvidencePrepared` predecessor. Only after both match may
execd sign the receipt and append a later `CompletionAvailable` record that
names its digest. The receipt never binds that later record or any encrypted
record containing itself.

`QueryByExecutionNonce` returns the complete signed effect-start receipt in
the `EffectStarted` and `CompletionAvailable` status variants and in every
`Indeterminate` whose journal has effect or known-effect ancestry, and
`FetchCompletion` repeats the same receipt and digest beside the completion
payload. A `ProviderRetryPrepared` head projects the retained prior-attempt
receipt; `ProviderResponseRetained` and `ReleaseEvidencePrepared` project the
current-attempt receipt. Execd resolves them only from the encrypted receipt
record and requires `SignedExecutorEffectStartedReceiptDigest` equality before
response encoding. The `Indeterminate` pair is both `None` only for a chain
with no `EffectStarted` or other known-effect lineage; either mixed option pair
or a receipt-free effect-lineage projection is noncanonical. Kerneld verifies
the service key/domain and persists the full signed bytes and digest in its WAL
before the corresponding terminal/quota transition or any known-success,
quarantine, or public-outcome transition. The final-release receipt is
recoverable from the encrypted completion payload and is retained until that
same kernel commit is acknowledged; a digest without either signed receipt
never proves effect start or final-release success.

```text
Absent
  → Prepared
  → ProviderAttemptPrepared
  → EffectStarted
  → ProviderResponseRetained
      ├──→ CompletionAvailable(ToolResult) → Acknowledged
      └──→ ReleaseEvidencePrepared
             → CompletionAvailable(FinalReleaseReceipt) → Acknowledged

Prepared | ProviderAttemptPrepared → FailedNoEffect
EffectStarted(no retained response)
  → ProviderRetryPrepared → EffectStarted                 // bounded retry
EffectStarted | ProviderRetryPrepared | ProviderResponseRetained |
ReleaseEvidencePrepared → Indeterminate
```

execd authenticates the complete kerneld transport and outer envelope
signature, verifies/decrypts the complete HPKE envelope, checks every
`DispatchCoreV2`, `DispatchSubjectV2`, and sealed-material field, then reads
only the fixed authenticated read-only ledger projection described in section
10.2. The manifest, deployment generation, and effect-fence epoch must equal
the core both when `Prepared` commits and immediately before codec/transport
preparation.
Execd has no root-ledger path or root-directory descriptor. A stale
generation/fence before effect produces `FailedNoEffect`; a fence transition
after `EffectStarted` is `Indeterminate` and cannot cause another call.

A partial frame cannot create a nonce or effect. `Prepared` and its nonce index
are durable before a codec job or provider transport attempt. Execd, including
for a descriptor declaring provider idempotency by execution nonce, fsyncs
the exact receipt-free first-attempt or retry-prepared predecessor, signs its
digest, persists the encrypted signed-receipt record, then appends and fsyncs
`EffectStarted` with both receipt references before
its first instruction that could emit a provider byte. The one-shot codec
worker has no network or credential and cannot satisfy this boundary. An
execd-owned provider retry is
permitted only when the signed tool descriptor selects
`ConnectorIdempotentByExecutionNonce`, its compiled
`BoundedConnectorRetryPolicyV2` still permits both the next attempt and
elapsed time, and execd reuses the byte-exact same execution nonce, core,
subject, sealed execution record, connector identity, and credential
binding while following the attempt-record rules above.
`ConnectorNonIdempotentSingleAttempt` permits exactly one provider transport
attempt. No worker or other service/recovery path retries a provider,
authorizes a replacement nonce, or makes an unjournaled call.

The typed completion remains encrypted and queryable until kerneld operation
62 confirms the exact completion descriptor and kernel commit digest.

### 13.3 Recovery

On boot, kerneld queries every nonterminal WAL entry by the original nonce,
core digest, and subject digest:

- `Unknown`: explicit resend is permitted only when kerneld's authenticated
  `KernelZeroByteSendProofV2` proves exactly zero bytes of the original frame
  were passed to the OS, the old connection is closed, and execd supplies the
  complete nonce-absence proof in section 5.4. Both proofs must bind the same
  core/subject/nonce, generation, fence, and journal heads. The resend uses
  the byte-exact sealed envelope, subject, and same nonce;
- `Prepared` or a first-attempt `ProviderAttemptPrepared`: expose prepared;
  `EffectStarted`, `ProviderRetryPrepared`, `ProviderResponseRetained`, or
  `ReleaseEvidencePrepared`: expose effect-started/dispatching until the
  directed successor is reconciled. A retry-prepared crash can resume only
  that exact attempt or become `Indeterminate`; it never returns
  `FailedNoEffect`;
- `CompletionAvailable`: fetch the exact typed payload; continue tool result
  gating for `ToolResult`, or verify/commit final-release
  receipt/audit/vault state for `FinalReleaseReceipt`;
- `FailedNoEffect`: terminal failure;
- `Indeterminate`: require the exact both-`Some`/both-`None` receipt option
  matrix above. When `Some`, verify and persist the full signed receipt before
  the terminal WAL/public-state/quota transaction. Both `None` is accepted
  only for authenticated execd state with no effect or known-effect lineage
  and cannot override a locally retained receipt or known-effect record;
- `Unknown` after any byte may have been written, missing absence proof, digest
  mismatch, corruption, unknown-after-effect, or any unprovable state:
  terminal `Indeterminate` and fail-stop for that action.

Kerneld keeps the exact subject attempt reserved and prohibits a new nonce
for that tool intent or final release until this
authenticated reconciliation reaches `EffectStarted`, known success,
`FailedNoEffect`, or terminal `Indeterminate`. It then atomically spends or
releases quota according to section 11.3. Execd's durable journal is the
truth at the external-byte boundary; no inferred agentd/kerneld state can
override it. Tool result recovery and final-release recovery use the same
nonce/core/subject state machine; their terminal evidence is type-checked
against `DispatchSubjectV2` before quota, vault, or public state changes.

No boot creates a replacement nonce. No `RecoveryReferenceV2` type or endpoint
exists. The durable task/index relationship updates `KernelTaskStatusV2`.
Agentd uses its signed correlation to query that status, then updates its own
public task ledger. After restart the public task handle remains query-only
and can reveal a content-free closed-enum status, including `Dispatching`
during reconciliation; it cannot authorize, dispatch, read content, cancel,
or release a vault.

If a tool result succeeds after the originating run is invalidated, kerneld may
construct a new recovery result vault and provenance rooted in the durable
dispatch record and execd receipt. It never recreates original ingress
plaintext or repeats the effect.

If a final release succeeds after the originating run is invalidated, kerneld
commits only the already-bound `DurableReleaseIdV2`, vault transition, signed
effect receipt, and content-free terminal task projection. It never recreates
release plaintext, changes destination/display/evidence, or repeats the
release.

## 14. Tool-result ingress

```text
ToolResultCompletionAvailableInExecd
  → ResultGating
  → ResultCommitted
  → ResultAcknowledged

failure:
ResultGatePending | EffectSucceededOutputQuarantined | Indeterminate
```

Raw tool results never enter JARVIS or agentd. kerneld applies:

- encoded/result-schema limits;
- indirect prompt-injection checks;
- PII/secret/NER detection;
- tokenization and a new immutable result vault segment;
- mandatory leak gates;
- result provenance bound to action intent, nonce, executor, tool, schema, and
  result digest.

Successful gating atomically creates a new immutable result vault segment,
value/provenance records, a bounded masked document, and one
`MaskedDocumentHandleV2`.
`PublicExecutionStatusV2::Succeeded {
completion: ToolExecution { document } }` returns that handle; agentd obtains
`AgentViewV2` only through `ReadAgentView`. Neither raw nor masked result is
automatically sent to the planner.

If gating is unavailable after an effect, state is `ResultGatePending` and
execd retains the encrypted result. Recovery reruns gating over only the same
nonce/result digest. It never repeats the effect. Operation 62 is sent only
after result and WAL commit.

If gating deterministically denies the result, kerneld atomically records
`EffectSucceededOutputQuarantined`, spent quota, result digest, denial class,
and the no-redispatch tombstone. It creates no agent-readable document.
Operation 62 may acknowledge deletion only after that quarantine record and
its audit record are durable; its `kernel_commit_digest` then identifies the
quarantine commit. A transient model or storage failure before a gating
decision is `ResultGatePending`. Once effect success and the exact result are
known, failure to durably publish the required kernel audit is instead the
terminal `EffectSucceededOutputQuarantined { class: Audit }`; execd remains
`CompletionAvailable` and retains the encrypted result until an authenticated
quarantine acknowledgement can be committed. It is never `Indeterminate`,
and no result-gating or audit outcome is ever mapped to `FailedNoEffect`.

For `DispatchSubjectV2::FinalRelease`, the completion gate accepts only
`ExecutorCompletionDescriptorV2::FinalReleaseReceipt` and the exact
`ExecutorCompletionPayloadV2::FinalReleaseReceipt` containing the exact
`SignedExecutorFinalReleaseReceiptV2`, provider evidence, and
`ExecutorFinalReleaseAuditEvidenceV2`. It recomputes the audit and evidence
digests, then verifies every subject/material/receipt duplicate and proves
the complete known-success predicate below. Only when the manifest-bound
release-evidence gate and the subsequent audit/publication gate both pass
does the success branch atomically commit signed release/audit evidence,
`DurablePublicOutcomeV2::FinalReleaseSucceeded`, the public task state, and
WAL completion together with the irreversible vault/quota/no-redispatch
transition described below. The public success is
`Succeeded { completion: FinalRelease }`; no document or result digest is
fabricated.

Final-release external success is known only when all of these are present and
equal under the same execution nonce: the fsynced signed effect-start receipt;
the encrypted retained exact provider response and digest; the
manifest-pinned connector success discriminant; the verified one-job codec
outcome attestation/transcript; and the signed final-release receipt matching
the exact core, release subject, vault segment, release-payload, destination,
executor, provider-evidence, receipt-free
`ReleaseEvidencePrepared` predecessor, and exact
`ExecutorFinalReleaseAuditEvidenceDigest`. No single
HTTP/provider status, codec claim, unsigned body, timeout, or availability
signal satisfies this predicate.

Once that predicate is true, the release is irreversible: the same terminal
transaction moves the vault to `Released`, moves the exact release quota to
`Spent`, and writes the no-redispatch nonce/release tombstone even when the
evidence is quarantined. The manifest-bound release-evidence gate runs before
the publication/audit gate. A deterministic evidence rejection therefore
produces only `ReleaseEvidence`; if evidence passed and the required
publication/audit commit fails, it produces only `Audit`. The two classes are
mutually exclusive for one release. If the known-success predicate itself
cannot be proved, the state is `Indeterminate`, quota is
`IndeterminateSpent`, and the vault is `Indeterminate`, never `Released` or
`FailedNoEffect`.

If the provider acknowledgement fails the manifest-bound release-evidence gate, the
terminal durable outcome is
`EffectSucceededOutputQuarantined {
evidence: DurableQuarantineEvidenceV2::FinalRelease { ... },
class: ReleaseEvidence }`. If that evidence gate succeeds but the required
kernel audit/publication commit fails, the terminal durable outcome is
`EffectSucceededOutputQuarantined {
evidence: DurableQuarantineEvidenceV2::FinalRelease { ... },
class: Audit }`. The receipt/evidence stays encrypted in execd until the
quarantine acknowledgement commits. If release effect or receipt identity
cannot be proved, the state is `Indeterminate`; it is never represented by a
tool `result_digest`, `FailedNoEffect`, or a replacement release.
Both `FinalReleaseSucceeded` and either final-release quarantine variant bind
the same final-release receipt digest and exact release-audit digest; a
different audit object, predecessor, outcome attestation, evidence digest, or
success discriminant is not another disposition of the same release.

## 15. GC, durable time, and retention

The dependency DAG is:

```text
task → run → value/provenance → plan revision → action intent
     → pending/approval/ticket → dispatch WAL → result vault/value

ingress grant → input session → approval → run/vault/agent claim

vault segment → release approval/ticket → dispatch WAL
```

Each object has an expiry-index entry. Foreground operations collect at most
128 objects; a background sweep collects at most 1,024 per tick. Parent
evidence remains as immutable tombstones until every descendant/action
retention deadline passes.

Persistent replay, approval, dispatch, and executor ledgers maintain a durable
`accepted_time_floor_ms`. Acceptance advances it monotonically and persists it
with the record. If OS wall time is below the floor, signed-time operations
fail-stop until an authorized clock-repair procedure. A consumed object never
becomes usable after clock rollback, even if an expiry tombstone would
otherwise age out.

## 16. Runtime security state

`SecurityStateManifestV2` is the only complete runtime state identity. It binds
release, ten-crate/binary closure, policy, registry, ontology, G1/G2/NER/OCR
models, resources, grammar/schema, `DestinationProjection`,
`DisplayProjection`, the internal validator set,
`ExecutorConnectorRegistry`, `ExecutorKeyLock`, `PlannerLock`, approval lock,
`ServiceIdentityLock`, sandbox/code-integrity profiles, JARVIS control
artifact, protocol suite, and persistent-store compatibility. Those named
locks are
independent required manifest identities; none may be inferred from a binary
digest or omitted because another registry happens to contain similar data.

The protocol-required replay/key portion of `ServiceIdentityLock` is:

```rust
enum ReplayKeyRoleV2 {
    AgentdJarvisControl = 1,
    IngressdBrowser = 2,
    AgentdAgentBrowser = 3,
    KerneldAgentKernel = 4,
    KerneldIngressKernel = 5,
    ExecdKernelExecutor = 6,
    ApprovaldAgent = 7,
    ApprovaldIngress = 8,
    ApprovaldAdmin = 9,
    ApprovaldBrowser = 10,
    AgentdJarvisBrowser = 11,
}

enum ReplayAeadAlgorithmV2 {
    XChaCha20Poly1305 = 1,
}

enum BootReplayKeySourceV2 {
    FreshLockedMemoryPerServerBoot = 1,
}

struct BootReplayKeyPolicyV2 {
    role: ReplayKeyRoleV2,
    algorithm: ReplayAeadAlgorithmV2,
    permitted_capsule_kinds: BoundedSortedVec<ReplayCapsuleKindV2, 7>,
    key_source: BootReplayKeySourceV2,
}

enum BootReplayKeyRuntimeStateV2 {
    Active {
        creation_entropy_health_digest: Digest32,
    } = 1,
    Destroyed {
        destroyed_at: UnixMillis,
        destruction_proof_digest: Digest32,
    } = 2,
}

struct BootReplayKeyRuntimeRecordV2 {
    schema_version: u16,                 // exactly 2
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    owning_service_identity: ServiceIdentityV2,
    server_boot_id: BootIdV2,
    role: ReplayKeyRoleV2,
    fresh_key_id: ReplayAeadKeyIdV2,
    locked_memory_handle_identity_digest: Digest32,
    created_at: UnixMillis,
    state: BootReplayKeyRuntimeStateV2,
}

struct ServiceIdentityLockProtocolPayloadV2 {
    schema_version: u16,                 // exactly 2
    protocol_abi_digest: Digest32,
    boot_replay_key_policies:
        BoundedSortedVec<BootReplayKeyPolicyV2, 11>,
    agentd_durable_replay_aead_lock_digest: Digest32,
    kerneld_task_correlation_key_id: Ed25519KeyIdV2,
    parser_worker_job_descriptor_key_id: Ed25519KeyIdV2,
    execd_connector_codec_job_descriptor_key_id: Ed25519KeyIdV2,
    execd_effect_receipt_key_id: Ed25519KeyIdV2,
}
```

The `permitted_capsule_kinds` set for each boot-fresh role is exact:

| `ReplayKeyRoleV2` | Exact strictly sorted `ReplayCapsuleKindV2` set |
|---|---|
| `AgentdJarvisControl` | `{ExactResponseSnapshot}` |
| `IngressdBrowser` | `{ExactResponseSnapshot, TypedCapabilityResponseEmission}` |
| `AgentdAgentBrowser` | `{ExactResponseSnapshot, TypedCapabilityResponseEmission}` |
| `KerneldAgentKernel` | `{ExactResponseSnapshot, TypedCapabilityResponseEmission, ActionIntentHandleEmission, ActionStateHandleEmission, ExecutionDocumentHandleEmission, ActionIntentEmissionReference}` |
| `KerneldIngressKernel` | `{ExactResponseSnapshot, TypedCapabilityResponseEmission}` |
| `ExecdKernelExecutor` | `{ExactResponseSnapshot}` |
| `ApprovaldAgent` | `{ExactResponseSnapshot, TypedCapabilityResponseEmission}` |
| `ApprovaldIngress` | `{ExactResponseSnapshot, TypedCapabilityResponseEmission}` |
| `ApprovaldAdmin` | `{ExactResponseSnapshot, TypedCapabilityResponseEmission}` |
| `ApprovaldBrowser` | `{ExactResponseSnapshot, TypedCapabilityResponseEmission}` |
| `AgentdJarvisBrowser` | `{TypedCapabilityResponseEmission}` |

Boot policies are strictly sorted by role and contain each of the eleven
replay-bearing daemon/browser boundaries exactly once, including the
independent 8765 `AgentdJarvisBrowser` role. Every row fixes
`XChaCha20Poly1305`, `FreshLockedMemoryPerServerBoot`, and byte-exact equality
with the corresponding set above. A missing, extra, duplicate, unsorted, or
cross-role substituted kind rejects the manifest. No boot-fresh role permits
`DurableTaskHandleEmission`. The deployment
`AgentdDurableReplayAeadLockV2` is outside these eleven policies and permits
exactly `{DurableTaskHandleEmission}`; it permits none of the six boot-only
kinds. A policy contains no key ID, epoch, keystore locator, persistent
master, retired key, or durable read edge.

At each server start the owning process generates a fresh nonexportable or
locked-memory key and authenticates one process-local
`BootReplayKeyRuntimeRecordV2` against the verified policy, service identity,
manifest/generation, and exact server boot. The runtime record and key are
never persisted. Active requires the entropy-health digest and has no
destruction fields; shutdown/crash handling destroys the memory/handle and
records only the content-free `Destroyed` audit proof. No next boot can
rederive, unwrap, retain, or list the old key. A runtime key ID or handle
identity from another service/role/boot is rejected before capsule lookup.
Replay capacity remains in `HardLimitsV2` and the resource profile.

`agentd_durable_replay_aead_lock_digest` binds the exact deployment-defined
`AgentdDurableReplayAeadLockV2`, which in turn authorizes the exact
deployment `ReplayCapsuleCompatibilityEdgeV2`. Protocol verification uses
that component's fields directly: `store_id`,
`persistent_store_compatibility_digest`, closed capability, protocol ABI, runtime
AEAD role, permitted epoch, retain-until, and `edge_identity_digest`. The only
permitted capability is read-existing
`DurableTaskHandleEmission`; boot/action-state/execution-document/cursor
emissions are never cross-manifest readable. Compatibility is denied without
the exact destination-manifest component and edge identity.

`ServiceIdentityLockProtocolPayloadV2` is authoritative only when the active
deployment-defined `ServiceIdentityLockV2` embeds it in the exact
`protocol_payload` field and embeds:

```text
ServiceIdentityLockProtocolPayloadDigest =
  SHA-256("savana.service-identity-lock.protocol-payload.v2\0" ||
          canonical_cbor(ServiceIdentityLockProtocolPayloadV2))
```

in the exact `protocol_payload_digest` field. The payload's durable replay
lock digest must equal:

```text
AgentdDurableReplayAeadLockDigest =
  SHA-256("savana.agentd-durable-replay-aead-lock.v2\0" ||
          canonical_cbor(AgentdDurableReplayAeadLockV2))
```

for the deployment lock's embedded `agentd_durable_replay_sealing` object.
Its task-correlation, parser-worker-descriptor,
connector-codec-job-descriptor, and effect-receipt key IDs must equal the
active `ServiceIdentityLockV2.ed25519_role_locks` key IDs for deployment
runtime roles 18, 22, 23, and 21 respectively. The deployment
`ExecutorKeyLockV2` projections for kerneld execution-envelope signing,
execd identity signing, execd effect-receipt signing, and execd
connector-codec-job-descriptor signing must be byte-identical to
`ServiceIdentityLockV2.ed25519_role_locks` roles 19, 20, 21, and 23. These
are duplicate verification projections, never a second rotation authority.
A missing payload, wrong payload or durable-lock digest, unresolved role,
or disagreeing duplicate fails manifest activation.

`kerneld_task_correlation_key_id` is the one active key authorized for both
`SignedDurableTaskCorrelationV2` and
`SignedAgentAuthenticationClosureDescriptorV2`; their different signature
domains prevent substitution. It is never accepted as the approvald closure
proof signer.

The root deployment ledger is the sole active/high-water authority. kerneld
does not maintain an independent competing release high-water. It opens the
root active manifest through a fixed descriptor, verifies the complete
closure, and publishes no listener until its exact digest is ready.

No request supplies or updates a policy, registry, ontology, model, resource,
projection, validator, executor, or approval snapshot. A change requires a
signed restart deployment transaction.

The exact manifest and rollback schema are defined by the deployment companion
specification.

## 17. V2 cryptographic suite

### 17.1 Suite 1

```text
ProtocolSuiteIdV2             1
key agreement                 ephemeral X25519
transcript authentication     Ed25519
KDF                           HKDF-SHA-256
digest                        SHA-256
record AEAD                   ChaCha20-Poly1305
sealed executor envelope      RFC 9180 HPKE base mode:
                              DHKEM(X25519, HKDF-SHA-256),
                              HKDF-SHA-256,
                              ChaCha20-Poly1305
at-rest journal AEAD          XChaCha20-Poly1305
replay capsule AEAD           XChaCha20-Poly1305
```

All implementations use pinned audited libraries and fixed vectors. No custom
cipher, KDF, signature, or nonce construction is permitted.

### 17.1.1 Closed signature ABI registry

Except the two handshake fields, every row uses section 3.1's exact
`[payload_bstr, Ed25519KeyIdV2, signature_bstr64]` representation. No other
signed artifact or signer is accepted.

| Signed artifact/field | Exact payload | Authorized signer | Exact Ed25519 input |
|---|---|---|---|
| `SignedToolDescriptorV2` | `UnsignedToolDescriptorV2` | active registry publisher key | `"SAVANA_TOOL_DESCRIPTOR_SIGNATURE_V2\0" || SHA-256("SAVANA_TOOL_DESCRIPTOR_V2\0" || payload_bstr)` |
| ingress `SignedApprovalEnvelopeV2` | `UnsignedApprovalEnvelopeV2` with purpose `Ingress` | active kerneld envelope key | ingress envelope domain from 11.4 `|| SHA-256(domain || payload_bstr)` |
| tool `SignedApprovalEnvelopeV2` | same, purpose `ToolExecution` | active kerneld envelope key | tool envelope domain from 11.4 `|| SHA-256(domain || payload_bstr)` |
| release `SignedApprovalEnvelopeV2` | same, purpose `FinalRelease` | active kerneld envelope key | release envelope domain from 11.4 `|| SHA-256(domain || payload_bstr)` |
| ingress `SignedApprovalSettlementV2` | `UnsignedApprovalSettlementV2` with purpose `Ingress` | active approvald ingress-settlement key | ingress settlement domain from 11.4 `|| SHA-256(domain || payload_bstr)` |
| tool `SignedApprovalSettlementV2` | same, purpose `ToolExecution` | active approvald tool-settlement key | tool settlement domain from 11.4 `|| SHA-256(domain || payload_bstr)` |
| release `SignedApprovalSettlementV2` | same, purpose `FinalRelease` | active approvald release-settlement key | release settlement domain from 11.4 `|| SHA-256(domain || payload_bstr)` |
| ingress/display/agent `SignedUiAuthenticationEnvelopeV2` | `UnsignedUiAuthenticationEnvelopeV2` with exact purpose, authentication origin, and return origin | active kerneld envelope key | purpose-specific UI envelope domain from 11.4 `|| SHA-256(domain || payload_bstr)` |
| ingress/display/agent `SignedUiAuthenticationSettlementV2` | `UnsignedUiAuthenticationSettlementV2` with exact purpose, authentication origin, and return origin | active approvald UI-auth settlement key | purpose-specific UI settlement domain from 11.4 `|| SHA-256(domain || payload_bstr)` |
| `SignedDurableTaskCorrelationV2` | `UnsignedDurableTaskCorrelationV2` | active kerneld task-correlation key | `"SAVANA_DURABLE_TASK_CORRELATION_V2\0" || SHA-256(payload_bstr)` |
| `SignedAgentAuthenticationClosureDescriptorV2` | `UnsignedAgentAuthenticationClosureDescriptorV2` | active kerneld task-correlation key | `"SAVANA_AGENT_AUTH_CLOSURE_DESCRIPTOR_V2\0" || SHA-256(payload_bstr)` |
| `SignedAgentAuthenticationAttemptClosureProofV2` | `UnsignedAgentAuthenticationAttemptClosureProofV2` | active approvald UI-auth settlement key | `"SAVANA_AGENT_AUTH_ATTEMPT_CLOSURE_PROOF_V2\0" || SHA-256(payload_bstr)` |
| `CompleteNonceAbsenceProofV2` | `UnsignedCompleteNonceAbsenceProofV2` | active execd identity key | `"SAVANA_EXECD_NONCE_ABSENCE_V2\0" || SHA-256(payload_bstr)` |
| `SignedExecutorEffectStartedReceiptV2` | `UnsignedExecutorEffectStartedReceiptV2` | active execd effect-receipt key | `"SAVANA_EXECD_EFFECT_STARTED_RECEIPT_V2\0" || SHA-256(payload_bstr)` |
| `SignedExecutorFinalReleaseReceiptV2` | `UnsignedExecutorFinalReleaseReceiptV2` | active execd effect-receipt key | `"SAVANA_EXECD_FINAL_RELEASE_RECEIPT_V2\0" || SHA-256(payload_bstr)` |
| `SignedParserWorkerJobDescriptorV2` | `UnsignedParserWorkerJobDescriptorV2` | active ingressd parser-job-descriptor key | `"SAVANA_PARSER_WORKER_JOB_DESCRIPTOR_SIGNATURE_V2\0" || SHA-256(payload_bstr)` |
| `SignedParserWorkerResultAttestationV2` | `UnsignedParserWorkerResultAttestationV2` | the one ephemeral result key embedded in the signed job descriptor | `"SAVANA_PARSER_WORKER_RESULT_SIGNATURE_V2\0" || SHA-256(payload_bstr)` |
| `SignedConnectorCodecJobDescriptorV2` | `UnsignedConnectorCodecJobDescriptorV2` | active execd connector-codec-job-descriptor key | `"SAVANA_CONNECTOR_CODEC_JOB_DESCRIPTOR_SIGNATURE_V2\0" || SHA-256(payload_bstr)` |
| `SignedConnectorCodecPreparedRequestAttestationV2` | `UnsignedConnectorCodecPreparedRequestAttestationV2` | the one ephemeral attestation key embedded in the signed codec job descriptor | `"SAVANA_CONNECTOR_CODEC_PREPARED_REQUEST_SIGNATURE_V2\0" || SHA-256(payload_bstr)` |
| `SignedConnectorCodecOutcomeAttestationV2` | `UnsignedConnectorCodecOutcomeAttestationV2` | the same one-job ephemeral attestation key | `"SAVANA_CONNECTOR_CODEC_OUTCOME_SIGNATURE_V2\0" || SHA-256(payload_bstr)` |
| `SignedSealedExecutionEnvelopeV2` | `SealedExecutionEnvelopePayloadV2` | active kerneld execution-envelope key | `"SAVANA_EXECD_ENVELOPE_SIGNATURE_V2\0" || SHA-256(payload_bstr)` |
| `ServerHelloBodyV2.server_signature` | no signed-object wrapper | endpoint server handshake key | `"SAVANA_SERVER_HELLO_V2\0" || TranscriptDigest` |
| `ClientFinishBodyV2.client_signature` | no signed-object wrapper | authenticated endpoint client handshake key | `"SAVANA_CLIENT_FINISH_V2\0" || TranscriptDigest || server_signature` |

### 17.2 Handshake

Each hello is exactly:

```text
hello_prefix_bstr16 || body_length_u32be || canonical_body
```

`body_length` is at most 16 KiB and must equal all remaining bytes. The body
schemas are:

```rust
enum RequestedModeV2 {
    Required = 1,
}

enum PeerIdentityBindingV2 {
    Linux {
        uid: u32,
        gid: u32,
        pid: u32,
        process_start_time: u64,
        executable_measurement: Digest32,
    } = 1,
    MacOs {
        audit_token: FixedBytesV2<32>,
        euid: u32,
        egid: u32,
        bundle_id: IdentifierV2,
        team_id: IdentifierV2,
        code_directory_digest: Digest32,
    } = 2,
}

struct ClientHelloBodyV2 {
    schema_version: u16,                 // exactly 2
    client_identity: ServiceIdentityV2,
    client_boot_id: BootIdV2,
    client_key_id: Ed25519KeyIdV2,
    client_nonce: Nonce32,
    client_ephemeral_x25519: FixedBytesV2<32>,
    requested_mode: RequestedModeV2,     // exactly Required
}

struct HandshakeTranscriptV2 {
    schema_version: u16,                 // exactly 2
    protocol_major: u16,                 // 2
    protocol_minor: u16,                 // 0
    suite_id: u16,                       // 1
    endpoint_role: EndpointRoleV2,
    requested_mode: RequestedModeV2,
    installation_id: Digest32,
    client_identity: ServiceIdentityV2,
    server_identity: ServiceIdentityV2,
    client_boot_id: BootIdV2,
    client_key_id: Ed25519KeyIdV2,
    server_key_id: Ed25519KeyIdV2,
    client_nonce: Nonce32,
    server_nonce: Nonce32,
    client_ephemeral_x25519: FixedBytesV2<32>,
    server_ephemeral_x25519: FixedBytesV2<32>,
    observed_client_peer: PeerIdentityBindingV2,
    server_boot_id: BootIdV2,
    active_state_manifest_sequence: u64,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    release_identity_digest: Digest32,
    model_set_identity_digest: Digest32,
    resource_profile_identity_digest: Digest32,
    approval_lock_identity_digest: Digest32,
    planner_lock_identity_digest: Digest32,
    executor_key_lock_identity_digest: Digest32,
}

struct ServerHelloBodyV2 {
    transcript: BoundedCanonicalBytesV2<16_KiB>,
    transcript_digest: Digest32,
    server_signature: Ed25519SignatureV2,
}

struct ClientFinishBodyV2 {
    transcript_digest: Digest32,
    server_signature: Ed25519SignatureV2,
    client_signature: Ed25519SignatureV2,
    client_confirm_mac: Digest32,
}
```

The server constructs the transcript from the exact accepted ClientHello,
locally observed peer, root ledger, active manifest, endpoint configuration,
and fresh server nonce/ephemeral key. The client decodes the transcript once
and requires every duplicated ClientHello and local-identity field to match.
`client_boot_id` is generated by the client service at process start and is
authenticated by the client signature over this transcript. It is the sole
source for replay-key client-boot binding and, on the AgentKernel edge, for
the `agentd_boot_id` copied into `AgentContent` UI-authentication bindings;
neither an operation body nor a browser may supply or override it.

```text
TranscriptDigest =
  SHA-256("SAVANA_HANDSHAKE_TRANSCRIPT_V2\0" ||
          canonical_cbor(HandshakeTranscriptV2))

server_signature =
  Ed25519.sign(server_handshake_key,
               "SAVANA_SERVER_HELLO_V2\0" || TranscriptDigest)

client_signature =
  Ed25519.sign(client_handshake_key,
               "SAVANA_CLIENT_FINISH_V2\0" ||
               TranscriptDigest ||
               server_signature)
```

Ed25519 verification is strict and rejects noncanonical signatures and
invalid/small-order public keys. X25519 public inputs are exactly 32 bytes; an
all-zero shared secret is rejected.

```text
salt =
  SHA-256("SAVANA_HANDSHAKE_SALT_V2\0" ||
          client_nonce || server_nonce)

prk = HKDF-Extract(salt, x25519_shared_secret)

session_context =
  SHA-256("SAVANA_SESSION_KEYS_V2\0" ||
          TranscriptDigest ||
          endpoint_role_u8)
```

Each output is exactly
`HKDF-Expand(prk, label_ascii_with_nul || session_context, output_length)`:

```text
"SAVANA_C2S_KEY_V2\0"         32 bytes
"SAVANA_S2C_KEY_V2\0"         32 bytes
"SAVANA_C2S_IV_V2\0"          12 bytes
"SAVANA_S2C_IV_V2\0"          12 bytes
"SAVANA_CLIENT_CONFIRM_V2\0"  32 bytes
"SAVANA_SERVER_CONFIRM_V2\0"  32 bytes
```

```text
client_confirm_mac =
  HMAC-SHA-256(client_confirm_key,
               "SAVANA_CLIENT_CONFIRM_MAC_V2\0" ||
               TranscriptDigest ||
               server_signature ||
               client_signature)

server_confirm_mac =
  HMAC-SHA-256(server_confirm_key,
               "SAVANA_SERVER_CONFIRM_MAC_V2\0" ||
               TranscriptDigest ||
               client_confirm_mac)
```

The server verifies the client signature and confirmation before accepting an
application record. Its first AEAD plaintext is exactly:

```rust
struct HandshakeAcceptedV2 {
    transcript_digest: Digest32,
    server_confirm_mac: Digest32,
}
```

The client
verifies both fields before treating the connection as authenticated. Any
failure closes silently.

### 17.3 Records

Suite 1 has no record fragmentation. Every request and every response is one
record; input larger than 256 KiB uses multiple authenticated connections and
`AppendInputChunk`, never multiple records in one request.

Closed values are:

```text
DirectionV2       1 ClientToServer, 2 ServerToClient
MessageKindV2     1 HandshakeAccepted, 2 ApplicationRequest,
                  3 ApplicationResponse
```

The exact frame is:

```text
ASCII "SV2R" ||
header_length_u16be ||
ciphertext_length_u32be ||
header_cbor ||
ciphertext_and_16_byte_tag
```

`header_length <= 512`; `ciphertext_length` is exactly
`plaintext_length + 16` and at most `8 MiB + 16`. The header is:

```rust
struct RecordHeaderV2 {
    protocol_major: u16,                // exactly 2
    protocol_minor: u16,                // exactly 0
    suite_id: u16,                       // exactly 1
    direction: DirectionV2,
    sequence: u64,
    endpoint_role: EndpointRoleV2,
    message_kind: MessageKindV2,
    request_id: RequestIdV2,
    operation_tag: u16,
    plaintext_length: u32,
    ciphertext_length: u32,
}
```

`HandshakeAccepted` uses server-to-client sequence 0, all-zero request ID, and
operation tag `65535`. An application request uses client-to-server sequence
0, a nonzero request ID, and its operation tag. Its response uses
server-to-client sequence 1 and repeats that ID/tag. No other record or
sequence is legal on the connection. Duplicate, gap, wrong direction, wrap,
extra record, early EOF, or trailing byte closes silently.

```text
nonce = direction_iv XOR encode_u96_big_endian(sequence)
```

`encode_u96_big_endian` is four zero bytes followed by the sequence as
unsigned big-endian u64. Associated data is:

```text
"SAVANA_RECORD_AAD_V2\0" ||
TranscriptDigest ||
exact_header_cbor
```

The clear framing lengths are checked against compiled ceilings before
allocation, but no request/body interpretation occurs before AEAD success.
Compression, rekey, padding negotiation, and additional records are forbidden.
All application records are encrypted. Payloads containing input, agent view,
planner envelope/plan, approval display/settlement, vault data, execution
envelope, or result additionally use the zeroizing content decoder. On the
response, any error, or close, implementations zeroize ephemeral private
values, shared secret, PRK, traffic keys/IVs, and confirmation keys.

### 17.4 Single-pass sensitive decode

Sensitive canonical validation performs one scan over the decrypted
zeroizing backing storage. It checks exact fixed-array length, shortest
encodings, closed tags, depth/item/byte limits, UTF-8/NFC requirements, and
complete consumption.

It does not validate by decoding, re-encoding, and comparing. Content strings
and bytes borrow from or move out of zeroizing storage, do not implement
`Clone`, and never enter ordinary `String`, ordinary `Vec<u8>`, formatted
`Debug`, or a second canonical encoding.

### 17.5 Persistent sealed envelope and journal keys

The execd HPKE public key/key ID and kerneld envelope-signing public key/key ID
are in `ExecutorKeyLock`. The unsigned outer payload is:

```rust
struct ExecutorSecretBindingV2 {
    slot: IdentifierV2,
    secret: ZeroizingBytesV2,
    secret_digest: Digest32,
}

enum SealedDispatchMaterialV2 {
    ToolExecution {
        tool_descriptor_digest: Digest32,
        materialized_arguments:
            BoundedSortedVec<(ArgumentNameV2, KernelValueV2), 256>,
        argument_digest: Digest32,
        provenance_set_digest: Digest32,
        destination: KernelValueV2,
        destination_digest: Digest32,
        token_set_digest: Digest32,
        secret_bindings: BoundedVec<ExecutorSecretBindingV2, 64>,
    } = 1,
    FinalRelease {
        durable_release_id: DurableReleaseIdV2,
        vault_segment_internal_id: Digest32,
        vault_segment_digest: Digest32,
        release_payload: ZeroizingBytesV2,
        release_payload_digest: Digest32,
        evidence_digest: Digest32,
        token_set_digest: Digest32,
        destination: KernelValueV2,
        destination_digest: Digest32,
        display_projection_digest: Digest32,
        display_digest: Digest32,
        executor_identity_digest: Digest32,
        release_quota_subject_digest: Digest32,
        secret_bindings: BoundedVec<ExecutorSecretBindingV2, 64>,
    } = 2,
}

struct SealedExecutionPlaintextV2 {
    schema_version: u16,                 // exactly 2
    dispatch_core_digest: Digest32,
    dispatch_subject_digest: Digest32,
    material: SealedDispatchMaterialV2,
    expires_at: UnixMillis,
}

struct SealedExecutionEnvelopePayloadV2 {
    schema_version: u16,                 // exactly 2
    core: DispatchCoreV2,
    dispatch_core_digest: Digest32,
    hpke_enc: FixedBytesV2<32>,
    hpke_ciphertext: BoundedBytesV2<7_MiB_plus_16>,
}
```

The HPKE plaintext is exactly the canonical
`SealedExecutionPlaintextV2` array and is at most 7 MiB before sealing.
Tool `materialized_arguments` and either variant's `secret_bindings` are
strictly increasing by argument/slot identifier and contain no duplicate. No
`InternalSlot` value is legal in this plaintext. The release payload remains
in zeroizing storage and is never copied to the WAL, audit log, result, status,
receipt, or public task ledger. Execd recomputes the subject, argument or
release-payload, destination, secret, token-set, executor-identity, and core
 digests before codec/transport preparation and requires the material variant to equal the
embedded `DispatchSubjectV2` tag. The 7 MiB bound leaves more than the maximum
canonical outer/signature overhead, so the complete `DispatchRequestV2`
always fits the 8 MiB application-record ceiling.

`SignedSealedExecutionEnvelopeV2` is the section 3.1 signed-object encoding of
that payload. The HPKE context is:

```text
hpke_info =
  "SAVANA_EXECD_HPKE_V2\0" ||
  canonical_cbor([
    installation_id,
    active_state_manifest_digest,
    deployment_generation,
    effect_fence_epoch,
    executor_identity,
    executor_key_id,
    execution_nonce
  ])

hpke_aad =
  "SAVANA_EXECD_HPKE_AAD_V2\0" ||
  canonical_cbor([
    dispatch_core_digest,
    dispatch_subject_digest,
    durable_task_id,
    durable_run_id,
    execution_nonce,
    executor_identity,
    expires_at
  ])

SealedEnvelopeDigest =
  SHA-256("SAVANA_SEALED_EXECUTION_ENVELOPE_V2\0" ||
          exact_signed_object_bytes)

outer_signature =
  Ed25519.sign(kerneld_envelope_key,
               "SAVANA_EXECD_ENVELOPE_SIGNATURE_V2\0" ||
               SHA-256(payload_bstr))
```

execd verifies the outer signature, core digest, and subject digest before
HPKE open, then requires the decrypted payload's duplicate digests and every
subject-specific material field to match. HPKE base mode supplies
confidentiality; the outer signature supplies sender authentication. Tool
result bytes and final-release receipts do not use a reverse HPKE envelope:
execd decrypts its at-rest record and returns zeroizing bytes only through
operation 63's mutually authenticated sensitive transport.

Transport-authentication, daemon-signing, HPKE unsealing, journal-encryption,
approval-signing, planner, and connector keys are distinct.

At-rest records use a platform-keystore master epoch key:

```rust
struct SealedJournalRecordV2 {
    schema_version: u16,                 // exactly 2
    service_identity: ServiceIdentityV2,
    installation_id: Digest32,
    active_state_manifest_digest: Digest32,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    record_id: Digest32,
    journal_sequence: u64,
    key_epoch: u64,
    nonce: FixedBytesV2<24>,
    ciphertext_and_tag: BoundedBytesV2<9_MiB>,
}
```

These envelope fields are authenticated cleartext, available before key
derivation, and repeated inside the encrypted record payload where applicable;
all duplicates must match exactly after open. No unauthenticated clear field
is used for state, ordering, dispatch, or expiry.

```text
record_prk = HKDF-Extract(record_id_bstr32, master_epoch_key)

record_key =
  HKDF-Expand(
    record_prk,
    "SAVANA_JOURNAL_RECORD_V2\0" ||
    canonical_cbor([
      service_identity,
      installation_id,
      key_epoch_u64,
      schema_version_u16
    ]),
    32)
```

Each record uses a CSPRNG-generated 24-byte XChaCha nonce. Exact AAD is:

```text
"SAVANA_JOURNAL_AAD_V2\0" ||
canonical_cbor([
  service_identity,
  installation_id,
  active_state_manifest_digest,
  deployment_generation,
  effect_fence_epoch,
  record_id,
  journal_sequence,
  key_epoch
])
```

Key lifecycle is normative:

| Key family | May create new objects while | Retirement dependency |
|---|---|---|
| handshake Ed25519 | exact `Ed25519KeyIdV2` is active for that edge | no session survives connection close; retired private key may be destroyed after listeners using it stop |
| kerneld envelope signing | exact `Ed25519KeyIdV2` is active | retain old public key while any dispatch/approval/UI-auth envelope signed by it is live; destroy retired private key after quiesce proves no signer can use it |
| kerneld task correlation | exact `Ed25519KeyIdV2` is active | retain verification key through every signed correlation/query tombstone expiry |
| execd HPKE unsealing | exact `HpkeX25519KeyIdV2` is active | retain retired private key while any prepared/sealed dispatch under it is live |
| four approval settlement families | exact family `Ed25519KeyIdV2`/epoch in `ApprovalLockV2` is active | retain old public key through every ceremony/envelope/settlement/credential/tombstone expiry; private key stops signing at retirement |
| journal master epoch | exact epoch is active | retain while any live encrypted record references it |
| planner mTLS / connector credential | exact lock entry is active | stop new use at fence transition; retain only where the closed provider reconciliation contract requires it |

At most four retired epochs per key family may be retained. Deployment refuses
a fifth rotation or deletion if the dependency DAG contains a live record,
prepared dispatch, result, settlement, tombstone, rollback reader, or recovery
object requiring the key. Once the last dependency and rollback-reader
deadline pass, the service deletes the platform-keystore slot, verifies it is
unavailable, zeroizes cached material, and appends a key-destruction audit
record. A retired key can verify/decrypt old bound objects but can never mint a
new request, approval, dispatch, result, or credential.

## 18. Negative API surface

V2 exposes no:

- trusted-value or capability constructor;
- `is_trusted`/`is_public` input;
- caller policy, active-tool, ontology, projection, validator, or model state;
- bare validator verdict;
- external validator declaration, attestation, key, route, or fallback;
- public `DetectStrict` or authoritative optional `LeakGate`;
- vault secret, raw entry enumeration, token resolve, or vault serialization;
- JARVIS data-bearing response;
- JARVIS conversation, action, execution, release, or recovery handle;
- user-derived planner free text;
- JARVIS/agentd tool credential or plaintext execution envelope;
- browser plaintext-release endpoint;
- loopback cookie, `Set-Cookie`, `Authorization`, WebSocket, CORS, or
  content-bearing JARVIS/bootstrap route;
- capability, task handle, digest, nonce, or expiry in any URL, header,
  cookie, browser storage, cache, referrer, or log, or a bootstrap selector
  anywhere except the one exact fixed 8765 selector path slot;
- `TaskHandleV2` in any non-JARVIS DTO, kernel object, semantic digest,
  approval, ingress, execution, release, or browser decoder;
- WebAuthn options, assertion, credential, challenge, or ceremony-completion
  field on AgentApproval or IngressApproval UDS;
- UI-authentication settlement accepted as an approval decision, approval
  settlement accepted as UI authentication, or one UI purpose's typed
  pre-auth/ceremony/transfer token decoded as another purpose;
- user-derived ingress bytes before `IngressInput` authentication, approval
  display bytes before `ApprovalDisplay` authentication, or `AgentViewV2`
  before `AgentContent` authentication;
- `PublicTaskStatusV2` embedded in `AgentViewV2`;
- 16-byte Ed25519/HPKE key ID or cross-family key-ID decoder;
- caller-supplied principal, approval display, challenge, decision, or boolean;
- deterministic production nonce helper;
- per-request model, parser, grammar, schema, or asset path;
- V1-to-V2 fallback decoder.

Compile-fail tests and symbol/route scans enforce this list.

## 19. Protocol/state completion gate

This specification is implemented only when:

- every DTO above has a fixed CBOR array, closed enum, compiled bound, docs,
  golden vector, invalid-field mutation matrix, and cross-role rejection test;
- all V1/V2 and endpoint-confusion vectors fail before dispatch;
- label joins, declassification, digests, ontology, projection, descriptor,
  planner, and validator rules pass differential/property tests;
- ingress, replay, action, quota, approval, vault, dispatch, result, journal,
  and recovery model tests cover every transition and crash point;
- handle tests iterate every row in section 3.5 against every other row's
  decoder, resolver, carrier, role, operation, purpose, origin, and restart
  state; all off-diagonal cases fail before lookup and every orphan
  issuer/consumer check is empty;
- UI-authentication tests cross all three purposes, typed pre-auth and
  ceremony capabilities, envelope/settlement domains, return origins, UDS
  roles, records, and transfer capabilities; they also reject display/input/
  AgentView access before authentication, decision-challenge reuse as UI
  authentication, UI challenge reuse as a decision, and any approval display
  byte before the local 8766 display session exists;
- URL/header/storage scans inject every handle, transfer, tab capability,
  nonce, digest, and expiry into path/query/fragment/userinfo, redirects,
  headers, cookies, logs, IndexedDB, Cache API, local/session storage, and
  service workers and prove rejection/no persistence; selectors are accepted
  only in the exact fixed 8765 bootstrap path slot and rejected everywhere
  else;
- public-task vectors assert the exact tags 1 through 14, reject unknown
  tags and `Some(None)`, prove logical-expiry `Expired` queries through
  `retain_until`, and prove `InvalidReference` only after that bound;
- task-ownership tests reject `TaskHandleV2` at every non-JARVIS decoder,
  reject task correlation on every non-AgentKernel role or mutation, and
  reject stale preparations for cancellation while preserving reconciliation
  through operation 41;
- HTTP-surface vectors enumerate every method/path on 8765, prove only the
  shell/bootstrap classes exist, inject forged/missing/cross-port `Origin`
  and every typed/raw TaskHandle encoding into every HTTP decoder, and prove
  rejection before selector/task lookup or response differentiation;
- task-origin vectors cross all four
  `(machine, JARVIS control client, agentd server, kerneld server)` boot
  identities: cancellation succeeds only on the exact creation tuple, any
  changed component is status-only, and tag-10 crashes at Reserved,
  request-may-have-sent, KernelCommitted, resolver/capsule publish, and
  response-loss boundaries converge on the original task/handle without
  losing the stored origin prefix;
- existing-run ingress races mutate the run revision between prepare,
  approval, and commit and prove the compare-and-swap failure changes no
  state; no JARVIS route can create a follow-up ingress;
- proposal replay tests prove the same proposal returns one intent's current
  canonical state without recreating pending state, changed bytes under the
  same proposal ID conflict, an already bound step cannot be rebound, and a
  fresh validated revision/step never gives the old intent a new nonce;
- planner semantic vectors substitute a slot ref from another ticket, alias
  two refs onto one slot, rebind a ref after validation, reorder or alter one
  relation semantic, and randomize every wire ref/envelope nonce. All
  cross-ticket/alias/rebind/relation changes reject, while random wire
  identifiers alone leave `InternalSlotDigestV2`, argument/provenance set
  digests, `PlanRevisionDigestV2`, intent, approval, dispatch, and WAL
  semantic bindings unchanged;
- claim-recovery vectors crash before/after pending-binding creation, approved
  commitment derivation, op39/op43 first transition, closure descriptor,
  approvald denylist/terminalization, proof return, old-attempt tombstone, and
  replacement publish. They prove exactly one commitment and one live attempt,
  reject old-envelope registration after denylisting, require the complete
  safe descendant-state matrix and manifest/store compatibility, never roll
  `AgentAuthPending` backward, and verify every `RestartInvalidated`
  prestate/disposition/claim/vault/retention option row;
- parser vectors reject a browser or ordinary append that names
  `ExtractedPage`, wrong descriptor signer, reused ephemeral key, persistent
  worker key, cross-job/channel frame, reordered/duplicated/gapped frame,
  wrong transcript/output/page/limit digest, and operation-50 attestation
  before a complete staged job; no failure commits an extracted channel;
- key tests reject truncated, padded, 16-byte, wrong-domain, and
  Ed25519/HPKE-cross-family IDs; approval-lock tests reject every unknown,
  duplicate, unsorted, wrong RP/origin, disallowed AAGUID/root pair, stale
  epoch, fifth retired key, rollback, and unpinned WebAuthn implementation;
- effect tests crash before and after every external-byte boundary for every
  connector transport, prove the receipt-free `ProviderAttemptPrepared`
  or `ProviderRetryPrepared` predecessor, its complete encrypted
  service-signed receipt record, and the later `EffectStarted` record form
  that exact acyclic order and are fsynced before the first byte. They reject
  a missing/early-deleted receipt record, digest-only status/fetch response,
  wrong signed bytes, and a retry-prepared crash relabeled
  `FailedNoEffect`,
  crash after execd terminalizes an effect-lineage item as `Indeterminate`
  but before kerneld first observes its signed receipt, require query recovery
  of the byte-exact receipt before kerneld terminal/quota commit, reject either
  `Some`/`None` mismatch and `None`/`None` for any `EffectStarted`,
  `ProviderRetryPrepared`, `ProviderResponseRetained`, or
  `ReleaseEvidencePrepared` ancestry, and permit `None`/`None` only when no
  effect or known-effect lineage exists,
  retain reserved quota until authenticated reconciliation, permit provider
  retry only with the same nonce/closed contract and strictly increasing
  durable attempt ordinal, and never mint a replacement nonce;
- connector-codec tests reject a worker network FD/credential/keystore
  handle, listener, wrong job signer, old descriptor on a new worker, reused
  ephemeral key, cross-job/channel frame, transcript reorder, response
  substitution, subject/completion cross-branch, changed stable retry field,
  skipped ordinal, over-limit retry, and every second non-idempotent provider
  attempt. They prove a worker can emit only the typed ephemeral-attested
  decoded outcome, reject any worker `ExecutorCompletionDescriptorV2`,
  execd receipt, service-key signature, audit digest, or journal digest, and
  prove final release follows
  `ReleaseEvidencePrepared → signed receipt → CompletionAvailable` without a
  reciprocal digest edge. Crashes immediately before and after
  `ProviderResponseRetained` prove the response is recoverable for codec-only
  replay and never causes a new provider byte;
- EffectGate race tests hold/release overlapping process-wide references,
  race the deployment exclusive lock against agentd operations 29/34 before
  kernel Prepared and before agentd replay/public commit, and prove every
  admitted WAL/marker/journal row is present in the exact deployment
  `FrozenEffectWorkSetV2`; owner-only terminal descendants match that set
  exactly before `QUIESCED`;
- audit-failure vectors prove known effect success/result plus failed kernel
  audit publication yields
  `EffectSucceededOutputQuarantined { class: Audit }` with spent quota and
  retained encrypted result, while `Indeterminate` occurs only when effect
  outcome cannot be proved;
- final-release vectors prove the exact known-success predicate, irreversible
  `Released` vault transition, Spent/IndeterminateSpent/ReleasedNoEffect quota
  transitions, no-redispatch tombstone, and mutually exclusive
  `ReleaseEvidence` versus `Audit` quarantine. They mutate every field of
  `ExecutorFinalReleaseAuditEvidenceV2`, substitute the evidence-prepared
  predecessor/worker attestation/success discriminant, and crash before and
  after evidence retention, receipt signing, and completion append; all
  digest cycles and tool/result/document/attempt-kind cross-branches reject;
- kerneld/execd restart recovery proves no replacement nonce and no lost
  unacknowledged result;
- browser tests cover every state-changing route in the source-origin/
  carrier/response/replay matrix; forged source origins and cross-carrier
  transfers fail before consumption. Exact replay verifies every capability
  and up to 4096 typed object-ref commitments; execution/release refresh keeps
  the immutable target ref, and cross-tab/type/boot/revision substitution
  fails;
- replay-capsule vectors cover every kind/context/key-binding combination,
  wrong role/scope/client/peer/object/manifest/generation/fence, XChaCha nonce
  collision reservation, AEAD/tag/plaintext/kind/resolver corruption, and
  client/internal context substitution. They require byte-exact equality with
  every row of the eleven-role permitted-kind matrix and reject
  extra/missing/duplicate/unsorted/cross-role kinds, every boot-fresh
  `DurableTaskHandleEmission`, and every non-durable kind under the durable
  escrow. Client corruption poisons only its mutation row; internal
  corruption poisons only the exact named emission record and every owner
  lookup then fails stop; neither reruns a mutation, recreates a resolver, or
  returns a partial response. Boot keys are unrecoverable after restart and
  only the deployment-locked durable escrow opens retained tag-10 handles;
- action-emission tests prove original and new-request same-proposal paths
  open the one `ActionIntentEmissionRecordV2` only for the same authenticated
  agentd/client/kerneld boot, while missing/cross-boot/cross-client records
  fail stop without re-mint; capacity reservation and GC retain every
  action-state/execution-document record while any live index can name it;
- sensitive fixed vectors cover handshake, key confirmation, record AAD,
  sequence, HPKE envelope, journal record, truncation, and zeroizing decode;
- capacity, GC, time rollback, and response-loss tests are mandatory and
  fail-closed;
- static source/IDL scans require zero legacy run-revision/planner-output/
  recovery-proof/result-operation/quarantine identifiers, zero protocol-local
  approval-lock/claim-compatibility/replay-edge signature schema, zero
  TaskHandle field in a non-JARVIS DTO, zero HTTP task-status/cancel route,
  zero generic replay decrypt/export route, zero OFD/flock EffectGate use, and
  an exact match between every signed artifact, enum tag, operation,
  handle/carrier row, signature domain, set-digest registry entry, and golden
  vector;
- no V2 mutation dispatcher is enabled before its individual gate passes.
