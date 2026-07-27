# Savana Kernel Protocol V1

Status: pre-release protocol `1.0` slice.

This document freezes the byte-level contract implemented by
`savana-kernel-protocol`, the signed policy and release identities consumed by
`savana-policy-core`, and the bootstrap contract enforced by
`savana-kerneld`.

The closed V1 schema includes authenticated `Health` and policy-transition
tags `10..19`. Until the policy engine integration lands, `savana-kerneld`
recognizes those policy tags but fails them closed with `KERNEL_UNAVAILABLE`;
schema availability is not authority to execute a transition.

Registry V1 signatures cover the existing domain-separated canonical message
directly:

```text
"SAVANA_REGISTRY_V1\0" || canonical_cbor(RegistrySnapshotV1)
```

The private registry version-chain identity is SHA-256 of those exact signing
bytes; it is not a wire field and Ed25519 does not sign that 32-byte digest.
For the empty version-1 snapshot `[1, null, [], 1000, 3000]`, canonical CBOR is
`8501f6801903e8190bb8` and the registry identity is
`f7cd24b33cd5cbfa8c04d913f55175c6dd3d54fa6873a3c3d541dddc233acc38`.

## Compatibility rules

- A signed V1 array is positional. A field cannot be added without a schema or
  protocol-minor revision.
- An existing signed array field cannot be removed, retyped, or reordered
  without a protocol-major revision.
- Enum tags and stable-code strings are permanent once shipped.
- Unknown message or operation tags fail closed.
- Unsigned policy, release, installation-profile, lock, handshake-state, peer
  credential, and connection-capability DTOs are not public Rust APIs.
- The per-connection capability is an opaque daemon-internal value. It is
  generated only after mutual authentication, cannot be constructed or read by
  callers, and is never serialized onto the wire.

## Transport and framing

The production transport is a filesystem Unix-domain stream socket. Peer
credentials are obtained from the kernel and checked against the signed
installation profile before the application handshake starts.

Each message is one frame:

1. Four bytes containing an unsigned big-endian payload length.
2. Exactly that many bytes containing one canonical CBOR value.

A zero-length frame is invalid. The compiled maximum payload is 8 MiB and a
signed policy may only lower it. A short header or short body is a truncated
frame. The daemon applies one absolute five-second I/O deadline to each complete
frame read or write; progress does not reset that deadline.

## Canonical CBOR

All CBOR exchanged or signed by this slice uses these restrictions:

- exactly one top-level value and no trailing bytes;
- definite-length arrays, byte strings, text strings, and maps only;
- shortest-width integer and length encodings;
- exact array lengths and exact numeric field positions;
- no tags, floats, undefined values, arbitrary simple values, or indefinite
  items;
- no unknown, duplicate, or missing map fields;
- no nesting deeper than the negotiated effective limit, whose compiled
  maximum is 32;
- byte and text values are bounded by the effective frame limit; and
- the original bytes must equal the bytes produced by the typed canonical
  encoder.

Wire messages use arrays and scalars only. `ResourceLimitsV1` is the one V1
numeric-key map. Its canonical keys are emitted in ascending order `0..24`.

Text identifiers (`KeyId`, `ClientId`, `ToolName`, `ValidatorId`, and
`ConstraintId`) contain 1 through 128 UTF-8 bytes and no Unicode control
characters. V1 does not apply Unicode normalization.

Fixed byte strings are:

| Type | Bytes |
| --- | ---: |
| `Digest32` | 32 |
| `Nonce32` | 32 |
| `BootId` | 32 |
| `Signature64` | 64 |
| `RequestId` | 16 |

`UnixMillis` is an unsigned 64-bit Unix timestamp in milliseconds.

## Wire messages

Every tagged union is encoded as `[tag, value]`.

### Scalar enum tags

| Type | Tag | Value |
| --- | ---: | --- |
| `RequestedMode` | 0 | `Required` |
| `RequestedMode` | 1 | `Shadow` |
| `AttemptKindV1` | 0 | `Read` |
| `AttemptKindV1` | 1 | `Create` |
| `AttemptKindV1` | 2 | `Update` |
| `AttemptKindV1` | 3 | `Delete` |
| `AttemptKindV1` | 4 | `Send` |
| `AttemptKindV1` | 5 | `Execute` |

### `ProtocolVersion`

Array length 2:

| Position | Field | Type |
| ---: | --- | --- |
| 0 | `major` | `u16` |
| 1 | `minor` | `u16` |

The only compiled version in this slice is `[1, 0]`.

### `ClientHelloV1`

Array length 5:

| Position | Field | Type |
| ---: | --- | --- |
| 0 | `client_nonce` | `Nonce32` |
| 1 | `supported_versions` | array of 1 through 16 unique `ProtocolVersion` values |
| 2 | `client_id` | `ClientId` |
| 3 | `client_key_id` | `KeyId` |
| 4 | `requested_mode` | `RequestedMode` |

The nonce must not be all zero.

### `ClientFinishV1`

Array length 2:

| Position | Field | Type |
| ---: | --- | --- |
| 0 | `transcript_digest` | `Digest32` |
| 1 | `signature` | raw Ed25519 `Signature64` |

### `RequestEnvelopeV1`

Array length 4:

| Position | Field | Type |
| ---: | --- | --- |
| 0 | `version` | `ProtocolVersion` |
| 1 | `request_id` | `RequestId` |
| 2 | `deadline_unix_ms` | `UnixMillis` |
| 3 | `operation` | `OperationV1` |

The request version must equal the authenticated version. The deadline must be
strictly in the future, no farther away than the effective
`request_deadline_ms`, and no later than the authenticated release/policy
expiry.

### `OperationV1`

| Tag | Value |
| ---: | --- |
| 0 | `Health`, encoded as `[0, []]` |
| 10 | `BeginRun(BeginRunRequest)` |
| 11 | `IngestUserInput(IngestUserInputRequest)` |
| 12 | `PreparePlannerCall(PreparePlannerCallRequest)` |
| 13 | `CommitPlannerValue(CommitPlannerValueRequest)` |
| 14 | `DeriveValue(DeriveValueRequest)` |
| 15 | `ProposeToolCall(ProposeToolCallRequest)` |
| 16 | `EvaluateToolCall(EvaluateToolCallRequest)` |
| 17 | `AuthorizeToolCall(AuthorizeToolCallRequest)` |
| 18 | `MaterializeExecution(MaterializeExecutionRequest)` |
| 19 | `CommitToolResult(CommitToolResultRequest)` |

Every operation remains `[tag, payload]`. The payload is a fixed array with
these fields:

| Tag | Length | Fields in position order |
| ---: | ---: | --- |
| 10 | 3 | `ingress`, `input`, `registry` |
| 11 | 3 | `run`, `envelope`, `input` |
| 12 | 3 | `run`, `planner`, `prompt_values` |
| 13 | 3 | `run`, `proof`, `value` |
| 14 | 3 | `run`, `operation`, `inputs` |
| 15 | 3 | `run`, `tool`, `arguments` |
| 16 | 2 | `pending`, `attestations` |
| 17 | 2 | `pending`, `receipt` |
| 18 | 1 | `ticket` |
| 19 | 2 | `ticket`, `result` |

`prompt_values` and derive `inputs` contain at most 256 items.
Decision-trace `rule_ids` contain at most 256 entries and are strictly
increasing and unique. Named arguments contain at most 256 entries and are strictly
sorted by unique `ArgumentName`. Validator attestations contain at most 32
entries and are strictly sorted by unique `ValidatorId`. Active-tool views
contain at most 256 entries and are strictly sorted by unique `ToolName`.
Every Task 1 collection described as sorted by text uses canonical CBOR text
order: compare UTF-8 byte length first, then compare UTF-8 bytes
lexicographically. Thus `"b"` sorts before `"aa"`. `AssembleObject(names)`
requires exactly one unique name per input; its `BoundedArgumentNames` preserves
the caller's input-to-name mapping order and is not sorted.

### Policy value and handle schema

`RunHandle`, `ValueHandle`, `ToolHandle`, `PlannerTicketHandle`,
`PendingToolCallHandle`, and `ExecutionTicketHandle` are exactly 32-byte CBOR
byte strings. Their Rust debug form is redacted and their fields and byte
constructors are private. Decode accepts no other width. A sealed issuance API
is intentionally deferred to the policy-engine integration; ordinary callers
do not receive a constructor.

`RoleId` is 1 through 64 UTF-8 bytes. `PrincipalId`, `ConversationId`,
`TaskId`, `ArtifactId`, and `PlannerId` are 1 through 128 UTF-8 bytes.
`ArgumentName` is a 1 through 64 byte ASCII identifier matching
`[A-Za-z_][A-Za-z0-9_]*`. These strings reject control characters.

`KernelValue` is `[tag, payload]`:

| Tag | Variant | Payload |
| ---: | --- | --- |
| 0 | `Null` | `null` |
| 1 | `Bool` | Boolean |
| 2 | `Integer` | `i64` |
| 3 | `Text` | `BoundedText` |
| 4 | `Bytes` | `BoundedBytes` |
| 5 | `List` | `BoundedList` |
| 6 | `Object` | `BoundedObject` |

`BoundedText` permits 0 through 65,536 UTF-8 bytes but rejects control
characters. `BoundedBytes` permits at most 1 MiB. `BoundedList` permits at most
1,024 values. `BoundedObject` is an array of at most 256
`[ArgumentName, KernelValue]` pairs, strictly sorted and unique by name under
canonical CBOR text order. Recursive decode and encode use one shared budget
per containing value: semantic depth 8, 65,536 nodes, 64 KiB aggregate text,
and 1 MiB aggregate value bytes. The semantic depth is deliberately lower than
the immutable global CBOR depth 32: in the deepest Task 1 wire path
(`EvaluateToolCall` `NeedsApproval` → signed approval envelope → masked
display), an object child consumes three CBOR levels, so semantic depth 8 puts
the deepest leaf payload at global depth 31 while depth 9 would exceed 32.
`MaskedDisplayBundleV1` shares one budget across both of its `KernelValue`
fields.

`DeriveOperation` is `[tag, payload]`: tags 0 `Concatenate`, 1
`NormalizeText`, 2 `SelectObjectField(ArgumentName)`, 3 `AssembleList`, and 4
`AssembleObject(BoundedArgumentNames)`. Unit payloads are `[]`.

### Producer and approval arrays used by policy operations

The schema declarations below are front-loaded because tags `10..19` cannot
be closed or decoded without them. Signature verification and policy-core
semantics are a later integration step.

| Type | Length | Fields in position order |
| --- | ---: | --- |
| `IngressEnvelopeV1` | 12 | `principal`, `conversation_id`, `request_digest`, `issued_at`, `expires_at`, `nonce`, `authority_session_id`, `authentication_context_digest`, `role`, `policy_digest`, `boot_id`, `connection_binding_digest` |
| `SignedIngressEnvelopeV1` | 3 | `unsigned`, `key_id`, `signature` |
| `SignedPlannerAttestationV1` | 10 | `run_id`, `planner_id`, `planner_version`, `prompt_digest`, `output_digest`, `issued_at`, `expires_at`, `nonce`, `key_id`, `signature` |
| `ToolExecutionIdentity` | 3 | `name`, `descriptor_digest`, `registry_version` |
| `ActiveToolView` | 2 | `handle`, `identity` |
| `ToolDescriptorV1` | 9 | `identity`, `provider_id`, `roles`, `input_schema_digest`, `output_schema_digest`, `attempt`, `constraint_ids`, `validator_ids`, `projection_digest` |
| `RegistrySnapshotV1` | 5 | `version`, `previous_digest`, `tools`, `issued_at`, `expires_at` |
| `SignedRegistrySnapshotV1` | 3 | `unsigned`, `key_id`, `signature` |
| `OntologyEntryV1` | 4 | `constraint_id`, `tool`, `effect`, `validator_id` (`null` or `ValidatorId`) |
| `OntologySnapshotV1` | 5 | `version`, `previous_digest`, `entries`, `issued_at`, `expires_at` |
| `OntologyEventV1` | 6 | `version`, `previous_digest`, `sequence`, `replacement`, `issued_at`, `expires_at` |
| `SignedOntologySnapshotV1` | 3 | `unsigned`, `key_id`, `signature` |
| `SignedOntologyEventV1` | 3 | `unsigned`, `key_id`, `signature` |
| `SignedValidatorAttestationV1` | 12 | `validator_id`, `validator_version`, `run_id`, `pending`, `argument_digest`, `verdict`, `public_reason`, `issued_at`, `expires_at`, `nonce`, `key_id`, `signature` |
| `ApprovalChallengeV1` | 14 | `challenge_id`, `purpose`, `subject`, `boot_id`, `run_id`, `principal`, `conversation_id`, `task_id`, `tool`, `destination_digest`, `policy_version`, `issued_at`, `expires_at`, `nonce` |
| `MaskedDisplayBundleV1` | 4 | `purpose_label`, `tool_label`, `masked_destination`, `masked_output` |
| `UnsignedApprovalEnvelopeV1` | 4 | `daemon_identity`, `challenge`, `display`, `display_digest` |
| `SignedApprovalEnvelopeV1` | 3 | `unsigned`, `daemon_key_id`, `signature` |
| `UnsignedApprovalReceiptV1` | 9 | `envelope_digest`, `challenge`, `decision`, `approval_principal`, `auth_method`, `approval_key_id`, `issued_at`, `expires_at`, `receipt_nonce` |
| `ApprovalReceiptV1` | 2 | `unsigned`, `signature` |

`request_digest` is the exact operation commitment:

```text
SHA-256("SAVANA_INGRESS_REQUEST_V1\0" ||
        canonical_cbor(IngressRequestCommitmentV1))
```

`IngressRequestCommitmentV1` is a closed tagged union whose canonical CBOR is
the exact outer array `[tag, payload]`:

| Tag | Variant | Exact payload |
| ---: | --- | --- |
| 0 | `BeginRun` | `[KernelValue]` |
| 1 | `IngestUserInput` | `[RunHandle, KernelValue]` |

Both the outer array and each payload require their exact stated length.
Unknown tags, missing or extra items, indefinite arrays, and non-canonical
children are rejected.

```text
BeginRun Null CBOR: 8200818200f6
BeginRun Null digest: 99dbaa60637f157d913d024ca99693f92ca8dba64490e8f6cbd0eeec20f99665
Ingest run=0x70*32, Null CBOR:
820182582070707070707070707070707070707070707070707070707070707070707070708200f6
Ingest digest: 5368417421be910eec040a38eebdb30744f67005890da2ce3cf17ecca7048da5
```

These enums are `[tag, payload]`:

| Type | Tag | Variant and payload |
| --- | ---: | --- |
| `PlannerCommitProofV1` | 0 | `DaemonTicket(PlannerTicketHandle)` |
| `PlannerCommitProofV1` | 1 | `SignedAttestation(SignedPlannerAttestationV1)` |
| `ApprovalSubjectV1` | 0 | `ToolCall([pending, argument_digest, provenance_digest])` |
| `ApprovalSubjectV1` | 1 | `VaultRelease([vault_session_id, evidence_digest, masked_output_digest, token_set_digest, artifact_id, artifact_generation])` |
| `ApprovalPurposeV1` | 0 | `ToolMaterialization([])` |
| `ApprovalPurposeV1` | 1 | `FinalRelease([])` |
| `ApprovalDecision` | 0 | `Approve([])` |
| `ApprovalDecision` | 1 | `Deny([])` |
| `ApprovalAuthMethod` | 0 | `WebAuthnUv([])` |
| `ValidatorVerdictV1` | 0 | `Pass([])` |
| `ValidatorVerdictV1` | 1 | `Fail([])` |
| `OntologyEffectV1` | 0 | `Allow([])` |
| `OntologyEffectV1` | 1 | `Deny([])` |
| `OntologyEffectV1` | 2 | `RequireValidator([])` |

Registry snapshots contain at most 256 tools, strictly sorted and unique by
tool name. Each descriptor contains at most 64 roles, 64 constraints, and 32
validators; each list is strictly sorted and unique by its canonical ID. Tool
names, roles, constraint IDs, and validator IDs all use the canonical CBOR text
order defined above. Registry snapshot versions are nonzero, and every
`ToolDescriptorV1.identity.registry_version` must equal its containing snapshot
version.

Ontology snapshots contain at most 100,000 entries, strictly sorted and unique
by `constraint_id` under the same canonical CBOR text order. Snapshot and event
versions are nonzero. `RequireValidator` requires a `validator_id`; `Allow` and
`Deny` require `validator_id = null`. A verified snapshot must also fit the
current verified policy's lower `max_snapshot_entries` value.

### Signed producer verification

The complete signed artifact is exact-decoded, must end at EOF, and must
byte-equal its canonical re-encoding before any key or signature decision.
Signature domains and signed payloads are fixed:

| Artifact | Domain | Canonical signed payload | Key source |
| --- | --- | --- | --- |
| policy bundle | `SAVANA_POLICY_V1\0` | policy bundle | installation policy trust root |
| ingress | `SAVANA_INGRESS_V1\0` | `IngressEnvelopeV1` | artifact `key_id`, fixed `Ingress` role in current verified policy |
| planner | `SAVANA_PLANNER_V1\0` | fixed array of the first 9 fields, including `key_id` | artifact `key_id`, fixed `Planner` role |
| registry | `SAVANA_REGISTRY_V1\0` | `RegistrySnapshotV1` | artifact `key_id`, fixed `Registry` role |
| ontology snapshot | `SAVANA_ONTOLOGY_SNAPSHOT_V1\0` | `OntologySnapshotV1` | allowlisted artifact `key_id`, fixed `Ontology` role |
| ontology event | `SAVANA_ONTOLOGY_EVENT_V1\0` | `OntologyEventV1` | allowlisted artifact `key_id`, fixed `Ontology` role |
| validator | `SAVANA_VALIDATOR_V1\0` | fixed array of the first 11 fields, including `key_id` | artifact `key_id`, fixed `Validator` role |
| approval envelope | `SAVANA_APPROVAL_ENVELOPE_V1\0` | `UnsignedApprovalEnvelopeV1` | daemon identity pinned by the verified installation release |
| approval receipt | `SAVANA_APPROVAL_RECEIPT_V1\0` | `UnsignedApprovalReceiptV1` | embedded `approval_key_id`, fixed `Approval` role |

No verification API accepts a domain string or caller-supplied public key.
Because wrapper payloads do not include their outer key ID, policy acceptance
rejects reuse of one active Ed25519 public key under multiple authority key
IDs. All active authority keys must decode as non-weak Ed25519 keys.
`planner_id` and `validator_id` must equal their signed key IDs.

Producer intervals are half-open: `policy.issued_at <= artifact.issued_at <=
now < artifact.expires_at <= policy.expires_at`, with the same containment in
the selected authority interval. Pure time failure is
`ATTESTATION_EXPIRED`; structural or identity containment failure uses the
artifact's binding code. Ingress, planner, validator, approval challenge, and
receipt nonces (and ingress authority-session ID) reject the all-zero value.
Approval challenge and receipt intervals must also fit the verified policy's
compiled TTLs, and the receipt interval must be contained in its challenge.

The approval display commitment is:

```text
SHA-256("SAVANA_APPROVAL_DISPLAY_V1\0" ||
        canonical_cbor(MaskedDisplayBundleV1))
```

Approval-envelope verification uses both `VerifiedReleaseIdentity` and
`VerifiedPolicyV1`: release target, daemon key ID, release/model/approval-key
digests, exact policy digest/version, resource-profile digest, and challenge
policy/boot self-binding are checked. This verifies a daemon- and
policy-authenticated envelope, but does not by itself prove that its boot ID is
the live boot seen on a separate connection. The Authority integration must
bind that identity to its authenticated daemon session. Likewise,
`VerifiedApprovalReceiptV1` is only a canonical, signature-, role-, policy-,
and time-verified artifact; final authorization still requires exact stored
challenge comparison and the one-time approval ledger.

Registry rollback/equivocation and ontology previous-digest/sequence state are
not single-artifact properties; the registry and ontology state machines apply
those checks when accepting an update.

### `ServerIdentityV1`

Array length 9:

| Position | Field | Type |
| ---: | --- | --- |
| 0 | `daemon_key_id` | `KeyId` |
| 1 | `boot_id` | `BootId` |
| 2 | `protocol` | `ProtocolVersion` |
| 3 | `release_digest` | `Digest32` |
| 4 | `policy_digest` | `Digest32` |
| 5 | `policy_version` | `u64` |
| 6 | `model_manifest_digest` | `Digest32` |
| 7 | `approval_key_set_digest` | `Digest32` |
| 8 | `resource_profile_digest` | `Digest32` |

### `HandshakeTranscriptV1`

Array length 3:

| Position | Field | Type |
| ---: | --- | --- |
| 0 | `client` | `ClientHelloV1` |
| 1 | `server_nonce` | `Nonce32` |
| 2 | `server` | `ServerIdentityV1` |

The server nonce and boot ID are independently generated nonzero 32-byte random
values.

### `SignedServerHelloV1`

Array length 2:

| Position | Field | Type |
| ---: | --- | --- |
| 0 | `transcript` | `HandshakeTranscriptV1` |
| 1 | `signature` | raw Ed25519 `Signature64` |

The connection binding committed by signed ingress is:

```text
SHA-256("SAVANA_CONNECTION_BINDING_V1\0" ||
        canonical_cbor(HandshakeTranscriptV1))
```

Before signing ingress, the Authority must obtain the complete daemon-signed
hello, verify its signature against the release-pinned daemon key and fixed
installation identity, and only then copy the selected policy digest and boot
ID and derive this connection binding from the verified transcript.

### `HandshakeAcceptedV1`

Array length 2:

| Position | Field | Type |
| ---: | --- | --- |
| 0 | `boot_id` | `BootId` |
| 1 | `protocol` | `ProtocolVersion` |

### `ResponseEnvelopeV1`

Array length 3:

| Position | Field | Type |
| ---: | --- | --- |
| 0 | `version` | `ProtocolVersion` |
| 1 | `request_id` | echoed `RequestId` |
| 2 | `body` | `ResponseBodyV1` |

`ResponseBodyV1` tags:

| Tag | Value |
| ---: | --- |
| 0 | success `ResponsePayloadV1` |
| 1 | error `StableCode` string |

`ResponsePayloadV1` tags:

| Tag | Value |
| ---: | --- |
| 0 | `HealthSnapshotV1` |
| 10 | `BeginRunResponse` array `[run, initial_value, active_tools]` |
| 11 | `ValueHandle` from `IngestUserInput` |
| 12 | `PlannerTicketHandle` |
| 13 | `ValueHandle` from `CommitPlannerValue` |
| 14 | `ValueHandle` from `DeriveValue` |
| 15 | `PendingToolCallHandle` |
| 16 | `EvaluateToolCallResponseV1` |
| 17 | `ExecutionTicketHandle` |
| 18 | `ExecutionEnvelope` array `[tool, arguments, argument_digest, execution_nonce]` |
| 19 | `ValueHandle` from `CommitToolResult` |

Success tags mirror request tags `10..19`; failures remain
`ResponseBodyV1::Err(StableCode)` rather than a second operation-specific
error union. `EvaluateToolCallResponseV1` uses tagged payloads: tag 0
`Denied([code, trace])`, tag 1
`NeedsApproval([SignedApprovalEnvelopeV1, trace])`, and tag 2
`Allowed([ExecutionTicketHandle, trace])`. Only this signed V1 approval
envelope is wire-visible; the internal unsigned policy binding is not.

`HealthSnapshotV1` is an array of length 3:

| Position | Field | Type |
| ---: | --- | --- |
| 0 | `ready` | Boolean |
| 1 | `identity` | `ServerIdentityV1` |
| 2 | `last_error` | `null` or `StableCode` string |

This pre-release slice reports `ready = false`; downstream policy, vault, and
NER plans define the transition to a ready product kernel.

### Top-level message tags

`ClientMessageV1`:

| Tag | Value |
| ---: | --- |
| 0 | `ClientHelloV1` |
| 1 | `ClientFinishV1` |
| 2 | `RequestEnvelopeV1` |

`ServerMessageV1`:

| Tag | Value |
| ---: | --- |
| 0 | `SignedServerHelloV1` |
| 1 | `HandshakeAcceptedV1` |
| 2 | `ResponseEnvelopeV1` |

The only valid flight order is:

```text
ClientHello -> SignedServerHello -> ClientFinish -> HandshakeAccepted
             -> one Request -> one Response -> close
```

## Negotiation and authentication

The client hello lists 1 through 16 unique versions. This implementation
selects exactly compiled version `1.0` only when:

- the client list contains `1.0`;
- the verified release declares protocol major `1`; and
- release `minimum_minor <= 0 <= maximum_minor`.

There is no implicit downgrade or selection of an uncompiled version.

Before the hello is accepted, the daemon checks the socket peer UID/GID against
an authorized `jarvis_kernel_client` in the signed installation profile. It
then resolves the exact `(client_id, client_key_id)` pair. Pending handshakes
expire after five seconds. Nonces and transcript digests are replay-protected
per configured client.

The authenticated context binds the peer credentials, client identity, boot
ID, negotiated version, requested mode, and the earlier of the verified release
and policy expiries.

## Signature and digest construction

All signatures are Ed25519 signatures over the exact byte concatenations below.
The trailing `\0` byte is part of each domain.

| Purpose | Exact input |
| --- | --- |
| Policy bundle | `b"SAVANA_POLICY_V1\0" || canonical_policy_bundle` |
| Release manifest | `b"SAVANA_RELEASE_V1\0" || canonical_release_manifest` |
| Daemon hello | `b"SAVANA_DAEMON_HELLO_V1\0" || canonical_handshake_transcript` |
| Client finish | `b"SAVANA_CLIENT_FINISH_V1\0" || transcript_digest` |

The transcript digest is exactly:

```text
SHA256(canonical_cbor(HandshakeTranscriptV1))
```

It is not a hash of the tagged server message, is not a hash of the framed
bytes, is not domain-prefixed, and is not double-hashed.

Five additional domain-separated hashes are identities, not signatures:

- `release_target_id = SHA256(b"SAVANA_RELEASE_TARGET_V1\0" ||
  canonical_release_target_array)`.
- `resource_profile_digest =
  SHA256(b"SAVANA_RESOURCE_PROFILE_V1\0" ||
  canonical_ResourceLimitsV1)`.
- `canonical_ledger_digest =
  SHA256(b"SAVANA_POLICY_LEDGER_V1\0" || canonical_ledger)`.
- `connection_binding_digest =
  SHA256(b"SAVANA_CONNECTION_BINDING_V1\0" ||
  canonical_cbor(HandshakeTranscriptV1))`.
- `request_digest =
  SHA256(b"SAVANA_INGRESS_REQUEST_V1\0" ||
  canonical_cbor(IngressRequestCommitmentV1))`.

`SAVANA_POLICY_LEDGER_V1\0` is a digest domain, not a signature domain.

The installation profile's policy-root binding is a fourth hash, but it has no
domain prefix:

```text
policy_trust_roots_digest =
    SHA256(canonical_cbor(profile.policy_trust_roots))
```

The hashed canonical CBOR includes the top-level array that contains all
`PolicyTrustRootV1` entries.

### `RollbackLedgerV1`

The local rollback ledger is canonical CBOR, not an Ed25519-signed envelope.
It is an array of length 4:

| Position | Field | Type |
| ---: | --- | --- |
| 0 | `schema_version` | `u16`, exactly `1` |
| 1 | `highest_policy_version` | `u64` |
| 2 | `highest_key_epoch` | `u64` |
| 3 | `highest_policy_digest` | `Digest32` |

Its canonical bytes must be the complete input to the ledger digest above.
The only genesis value is `[1, 0, 0, h'00…00']`. Any non-genesis accepted
value has nonzero `highest_policy_version`, nonzero `highest_key_epoch`, and a
nonzero digest. Mixed zero/nonzero states are rejected.

## Signed policy schema

`PolicyBundleV1` is a signed array of length 17:

| Position | Field | Type |
| ---: | --- | --- |
| 0 | `schema_version` | `u16` |
| 1 | `protocol` | `ProtocolRangeV1` |
| 2 | `policy_version` | `u64` |
| 3 | `key_epoch` | `u64` |
| 4 | `issued_at` | `UnixMillis` |
| 5 | `expires_at` | `UnixMillis` |
| 6 | `signing_key_id` | `KeyId` |
| 7 | `dataflow` | `DataflowPolicyV1` |
| 8 | `attempts` | `AttemptPolicyV1` |
| 9 | `ontology` | `OntologyPolicyV1` |
| 10 | `sink` | `SinkPolicyV1` |
| 11 | `release` | `ReleasePolicyV1` |
| 12 | `tools` | array of `AllowedToolV1` |
| 13 | `authorities` | array of `AuthorityKeyV1` |
| 14 | `resources` | `ResourceLimitsV1` |
| 15 | `accepted_model_manifest_digests` | array of `Digest32` |
| 16 | `error_map` | array of `StableErrorMappingV1` |

Nested policy arrays:

| Type | Array positions |
| --- | --- |
| `ProtocolRangeV1` | 0 `major`, 1 `minimum_minor`, 2 `maximum_minor` |
| `DataflowPolicyV1` | 0 `no_side_effect_tools`, 1 `consent_overridable_tools`, 2 `high_risk_tools` |
| `ToolAttemptV1` | 0 `tool`, 1 `attempt` |
| `AttemptLimitV1` | 0 `attempt`, 1 `maximum_per_run` |
| `AttemptPolicyV1` | 0 `valid_pairs`, 1 `limits`, 2 `cloud_blocked` |
| `OntologyPolicyV1` | 0 `snapshot_authority_key_ids`, 1 `max_snapshot_entries`, 2 `max_constraints_per_tool` |
| `ToolValidatorRequirementV1` | 0 `tool`, 1 `validator_ids` |
| `SinkPolicyV1` | 0 `validator_requirements`, 1 `deny_on_missing_attestation` |
| `ReleasePolicyV1` | 0 `challenge_ttl_seconds`, 1 `receipt_ttl_seconds`, 2 `require_authenticated_user_assertion`, 3 `consume_vault_on_success`, 4 `compatible_release_target_ids` |
| `AllowedToolV1` | 0 `name`, 1 `descriptor_digest`, 2 `attempt`, 3 `constraint_ids`, 4 `validator_ids` |
| `AuthorityKeyV1` | 0 `key_id`, 1 `role`, 2 raw 32-byte `public_key`, 3 `epoch`, 4 `not_before`, 5 `not_after`, 6 `revoked` |
| `StableErrorMappingV1` | 0 `policy_reason_tag`, 1 `stable_code` |

`AuthorityRoleV1` scalar tags are:

| Tag | Role |
| ---: | --- |
| 0 | `Ingress` |
| 1 | `Planner` |
| 2 | `Registry` |
| 3 | `Ontology` |
| 4 | `Validator` |
| 5 | `Approval` |
| 6 | `ModelManifest` |
| 7 | `Release` |

`ResourceLimitsV1` is a map with exactly 25 unsigned entries:

| Key | Field | Compiled maximum |
| ---: | --- | ---: |
| 0 | `frame_bytes` | 8,388,608 |
| 1 | `cbor_depth` | 32 |
| 2 | `pages` | 2,048 |
| 3 | `chars_per_page` | 50,000 |
| 4 | `chars_per_document` | 1,000,000 |
| 5 | `observations` | 100,000 |
| 6 | `vault_entries` | 20,000 |
| 7 | `vault_raw_bytes` | 33,554,432 |
| 8 | `runs_per_client` | 128 |
| 9 | `vaults_per_client` | 512 |
| 10 | `approval_ledger_entries` | 65,536 |
| 11 | `model_manifest_bytes` | 262,144 |
| 12 | `model_assets` | 32 |
| 13 | `model_tensor_contracts` | 32 |
| 14 | `model_tensor_rank` | 8 |
| 15 | `single_model_asset_bytes` | 268,435,456 |
| 16 | `total_model_asset_bytes` | 536,870,912 |
| 17 | `ner_workers` | 4 |
| 18 | `ner_queue` | 128 |
| 19 | `ner_text_bytes` | 200,000 |
| 20 | `model_probes` | 16 |
| 21 | `model_probe_spans` | 512 |
| 22 | `ner_failure_threshold` | 32 |
| 23 | `request_deadline_ms` | 120,000 |
| 24 | `ingress_replay_entries_per_client` | 4,096 |

Every requested value must be less than or equal to its compiled maximum.

### Policy acceptance, ordering, and collection bounds

The policy decoder accepts the 17-field signed array only when its complete
canonical encoding is at most the compiled 8 MiB `HardLimits::frame_bytes`,
every nested fixed array has the length shown above, and each bounded vector is
no larger than the following compiled maximum. The policy's own `resources`
cannot lower the bound used to decode that same policy: only after canonical
decode, external-trust-root selection, strict signature verification, and
policy validation are those resource values lowered into effective limits for
subsequent protocol work. A zero-length vector is permitted at decode time
unless a later acceptance rule below requires it to be nonempty.

| Collection | Maximum elements |
| --- | ---: |
| `tools` | 256 |
| `authorities` | 64 |
| `error_map` | 256 |
| `accepted_model_manifest_digests` | 32 |
| each dataflow tool list | 256 |
| `valid_pairs` | 1,536 |
| `limits` and `cloud_blocked` | 6 each |
| `snapshot_authority_key_ids` | 16 |
| `validator_requirements` | 256 |
| each requirement's `validator_ids` | 32 |
| each tool's `constraint_ids` | 64 |
| each tool's `validator_ids` | 32 |
| `compatible_release_target_ids` | 16 |

Every list described as sorted below is *strictly* increasing, so it is also
unique. The text comparator is canonical CBOR text-key order: compare UTF-8
byte lengths first, then compare UTF-8 bytes lexicographically. The exact
ordered/unique lists are `tools.name`, `authorities.key_id`, every individual
dataflow tool list, `ontology.snapshot_authority_key_ids`,
`sink.validator_requirements.tool`, every tool's `constraint_ids` and
`validator_ids`, and every validator requirement's `validator_ids`.

`valid_pairs` is strictly ordered by `(tool name in that text order, attempt
tag)`. `limits` and `cloud_blocked` are strictly ordered by increasing attempt
tag. `compatible_release_target_ids` and
`accepted_model_manifest_digests` are strictly ordered by raw 32-byte
lexicographic order. `error_map` is strictly ordered by increasing
`policy_reason_tag`. No other cross-list disjointness is imposed by this V1
validator.

Additional acceptance rules are:

- `schema_version` is 1; `protocol.major` is 1; `minimum_minor <= 0` (the
  compiled minor); `policy_version` and `key_epoch` are nonzero; and
  `issued_at < expires_at`, with `issued_at <= now < expires_at`.
- `challenge_ttl_seconds` and `receipt_ttl_seconds` are each `1..=120`;
  `max_snapshot_entries` is `1..=100000`;
  `max_constraints_per_tool` is `1..=64`; and every
  `AttemptLimitV1.maximum_per_run` is `1..=65536`.
- `require_authenticated_user_assertion`, `consume_vault_on_success`, and
  `deny_on_missing_attestation` are all exactly `true`.
- Every dataflow tool and every `valid_pairs.tool` names an entry in `tools`;
  every allowed tool has its exact `(name, attempt)` in `valid_pairs`.
- Every authority has the base structural constraints of nonzero epoch and
  public key plus `not_before < not_after`. Separately, at least one authority
  for every one of the eight `AuthorityRoleV1` tags must be active for the
  whole policy interval: not revoked, `not_before <= issued_at`, and
  `not_after >= expires_at`. Extra revoked authorities and extra authorities
  whose validity window covers only part of the policy interval are allowed
  when the per-role active requirement is still met.
- Every snapshot authority names an active `Ontology` authority. Every tool
  validator names an active `Validator` authority. Each sink requirement names
  an existing tool, has at least one validator, and is a subset of that tool's
  listed validators. These referenced snapshot and validator entries are the
  only bundle fields that impose an additional active/role condition during
  initial validation; later role-qualified authority lookup likewise returns
  only an exact-role authority active for the whole policy interval.
- `compatible_release_target_ids` and `accepted_model_manifest_digests` are
  both nonempty, and the former contains the active release target. The former
  otherwise has only the 16-element decoder cap above.

### External policy trust roots

The `AuthorityKeyV1` entries inside the signed bundle do not establish trust in
that bundle's signer. Signing trust comes only from the installation profile's
external `policy_trust_roots`, whose complete canonical array is bound by
`policy_trust_roots_digest` above.

That profile array contains 1 through 16 roots, strictly ordered/unique by
`key_id`. Every root has a nonzero epoch and public key, and release-profile
validation requires every public key to parse as an Ed25519 verifying key and
not be weak. To verify a policy, the verifier selects the external root whose
`key_id` equals `PolicyBundleV1.signing_key_id`, then requires equal root and
bundle epochs and `revoked = false`. It parses the selected Ed25519 key and
uses `verify_strict` over
`b"SAVANA_POLICY_V1\0" || canonical_policy_bundle`; strict verification applies
the strict Ed25519 malleability checks and rejects small-order public-key and
signature-R points. Failure at any selection, parse, or signature step is
`POLICY_INVALID_SIGNATURE`.

## Signed release schema

`ReleaseManifestV1` is a signed array of length 25:

| Position | Field | Type |
| ---: | --- | --- |
| 0 | `schema_version` | `u16` |
| 1 | `release_version` | bounded text |
| 2 | `release_sequence` | `u64` |
| 3 | `release_target_id` | `Digest32` |
| 4 | `source_commit` | exactly 40 or 64 lowercase hexadecimal characters |
| 5 | `signing_key_id` | `KeyId` |
| 6 | `binary_sha256` | `Digest32` |
| 7 | `cargo_lock_sha256` | `Digest32` |
| 8 | `rust_toolchain_sha256` | `Digest32` |
| 9 | `protocol_major` | `u16` |
| 10 | `minimum_minor` | `u16` |
| 11 | `maximum_minor` | `u16` |
| 12 | `supported_policy_schemas` | sorted unique array of `u16` |
| 13 | `supported_model_schemas` | sorted unique array of `u16` |
| 14 | `policy_trust_roots_digest` | `Digest32` |
| 15 | `minimum_policy_version` | `u64` |
| 16 | `model_manifest_digest` | `Digest32` |
| 17 | `producer_registry_digest` | `Digest32` |
| 18 | `ontology_digest` | `Digest32` |
| 19 | `approval_key_set_digest` | `Digest32` |
| 20 | `resource_profile_digest` | `Digest32` |
| 21 | `installation_profile_digest` | `Digest32` |
| 22 | `payloads` | canonically sorted array of `ReleaseFileV1` |
| 23 | `issued_at` | `UnixMillis` |
| 24 | `expires_at` | `UnixMillis` |

`ReleaseFileV1` is `[relative_path, byte_length, sha256]`. Relative paths are
sorted using canonical CBOR text-key order: UTF-8 byte length first, then
bytewise lexical order.

The release-target input is an array of length 7:

| Position | Field |
| ---: | --- |
| 0 | `protocol_major` |
| 1 | `minimum_minor` |
| 2 | `maximum_minor` |
| 3 | `supported_policy_schemas` |
| 4 | `policy_trust_roots_digest` |
| 5 | `resource_profile_digest` |
| 6 | `installation_profile_digest` |

`KernelInstallationProfileV1` is an array of length 14:

| Position | Field | Type |
| ---: | --- | --- |
| 0 | `schema_version` | `u16` |
| 1 | `installation_id` | `Digest32` |
| 2 | `platform` | tag: 0 Linux, 1 macOS |
| 3 | `daemon_identity` | `InstallationPublicKeyV1` |
| 4 | `daemon_clients` | array of `InstallationClientV1` |
| 5 | `policy_trust_roots` | array of `PolicyTrustRootV1` |
| 6 | `daemon_uid` | `u32` |
| 7 | `daemon_gid` | `u32` |
| 8 | `jarvis_uid` | `u32` |
| 9 | `socket_path` | absolute path text |
| 10 | `selected_policy_path` | absolute path text |
| 11 | `selected_policy_signature_path` | absolute path text |
| 12 | `socket_parent_mode` | `u16` permission bits |
| 13 | `socket_mode` | `u16` permission bits |

Nested installation arrays:

| Type | Array positions |
| --- | --- |
| `InstallationPublicKeyV1` | 0 `key_id`, 1 raw 32-byte `public_key` |
| `InstallationClientV1` | 0 `client_id`, 1 `key_id`, 2 raw 32-byte `public_key`, 3 `role`, 4 `peer_uid`, 5 `peer_gid` |
| `PolicyTrustRootV1` | 0 `key_id`, 1 raw 32-byte `public_key`, 2 `epoch`, 3 `revoked` |
| `ReleaseTrustRootV1` | 0 `key_id`, 1 raw 32-byte `public_key`, 2 `not_before`, 3 `not_after`, 4 `revoked` |

The only installation-client role tag is `0 =
JarvisKernelClient`.

### Release and installation acceptance rules

The release manifest, installation profile, and serialized release-root input
must be complete canonical CBOR values; each `ReleaseFileV1` is canonical as
part of its manifest. Payload file contents are instead checked by declared
length and SHA-256. `release_version` and all identifier fields use UTF-8 byte
counts; identifiers and `release_version` are 1 through 128 bytes with no
Unicode control character. `source_commit` is the exception: it is exactly 40
or exactly 64 bytes and every byte is `0-9` or `a-f`; uppercase hexadecimal is
rejected, as is `g` or any other non-hexadecimal character.

The release manifest has `payloads` length `1..=48` (the compiled 32 model
assets plus 16 non-asset slots). Each schema-version list has length `1..=16`
and is strictly increasing by numeric `u16` value, therefore unique. Payloads
are strictly increasing by relative path under the same canonical text
comparator used for policy strings, therefore unique. Installation client and
policy-root lists have length `1..=16`; clients are strictly ordered/unique by
`client_id`, and policy roots by `key_id`, using that text comparator. The
bootstrap release-root list is likewise `1..=16` and strictly ordered by
`key_id` under that comparator.

The trusted release-root set has 1 through 16 entries, strictly ordered/unique
by `key_id` under that comparator; every root has a nonzero public key and
`not_before < not_after`. The allowed release-digest set has 1 through 16
nonzero entries, strictly increasing by raw 32-byte lexicographic order. A
release is considered only when its SHA-256 manifest digest is in that set, and
its signing root is non-revoked and satisfies `not_before <= now < not_after`.

For a release to be accepted, `schema_version` and `protocol_major` are 1,
`minimum_minor <= 0`, both supported-schema lists contain 1, `release_sequence`
and `minimum_policy_version` are nonzero, `issued_at < expires_at`, and
`issued_at <= now < expires_at`. The release target, binary, Cargo lock, Rust
toolchain, policy-root, model, registry, ontology, approval-key, resource,
installation-profile, and every payload digest must all be nonzero. The signed
release target must equal the release-target digest construction above. No
additional direct relation between `minimum_minor` and `maximum_minor` is
imposed by this release validator beyond their unsigned-`u16` encoding.

An installation profile has schema version 1, a nonzero installation digest and
daemon public key, nonzero daemon UID/GID and JARVIS UID, and distinct daemon
and JARVIS UIDs. Its public keys must parse as non-weak Ed25519 verifying keys.
Its socket-parent and socket modes are exactly `0750` and `0660`; the three
absolute paths must exactly equal the selected platform paths below. Every
client has a nonzero public key and GID, peer UID equal to `jarvis_uid`, role
0, and a key ID and public key different from the daemon identity. Client key
IDs and public keys are individually unique. All clients share their first
client's GID, and that GID differs from `daemon_gid`. Each policy root has a
nonzero public key and nonzero epoch. A decoded empty client list is rejected
when the first client's GID is required. The decoder requires the policy-root
list itself to contain 1 through 16 entries, so it can never be empty.

`relative_path` is UTF-8 text of 1 through 256 bytes. It must not start with
`/`, contain `\\`, NUL, or a Unicode control character, and every `/`-separated
component must be nonempty and neither `.` nor `..`. It must then match exactly
one of the permitted names:

- `bin/savana-kerneld`
- `policy/default-policy-v1.cbor`
- `policy/default-policy-v1.sig`
- `approval/producer-registry-v1.cbor`
- `approval/ontology-v1.cbor`
- `approval/approval-key-set-v1.cbor`
- `model/signed-model-manifest-v1.cbor`
- `installation/kernel-installation-profile-v1.cbor`
- `runtime/libonnxruntime.so` or `runtime/libonnxruntime.dylib`
- a path beginning exactly `model/assets/` (and still satisfying the component
  rules above).

All eight fixed payload names must be present. There must be exactly one path
beginning `runtime/`, and it must be `runtime/libonnxruntime.so` for Linux or
`runtime/libonnxruntime.dylib` for macOS. There must be 1 through 32 paths
beginning `model/assets/`. The binary payload digest must equal
`binary_sha256`; the installation-profile payload digest must equal
`installation_profile_digest`.

Every payload byte length is nonzero. Maximum lengths are 128 MiB for the
daemon executable; 8 MiB each for the installation profile and default policy;
256 KiB for the signed model manifest; 256 MiB for each model asset and the
single runtime; and 64 MiB for every other payload (including the policy
signature and approval files). The policy signature is exactly 64 bytes. The
sum of model assets is at most 512 MiB. The complete descriptor-anchored stage
limit is:

```text
manifest byte length + 64-byte release signature
    + Σ declared payload byte lengths <= 1 GiB
```

The release manifest and installation profile files themselves are at most
8 MiB; the installation profile is one of the declared payloads in the sum.

Absolute profile path text is 1 through 256 bytes, begins with `/`, and
contains no Unicode control character; exact platform matching makes any other
spelling reject. The compiled platform alternatives are:

| Platform | runtime payload | socket | selected policy | selected-policy signature |
| --- | --- | --- | --- | --- |
| Linux (tag 0) | `runtime/libonnxruntime.so` | `/run/savana/kernel/kerneld.sock` | `/etc/savana/kernel/selected-policy-v1.cbor` | `/etc/savana/kernel/selected-policy-v1.sig` |
| macOS (tag 1) | `runtime/libonnxruntime.dylib` | `/var/run/savana/kernel/kerneld.sock` | `/Library/Application Support/Savana/Kernel/selected-policy-v1.cbor` | `/Library/Application Support/Savana/Kernel/selected-policy-v1.sig` |

Descriptor-anchored production stage verification additionally requires the
profile platform to match the platform on which the daemon was compiled.

## Bootstrap JSON

The daemon binary accepts exactly:

```text
savana-kerneld --config /etc/savana/kerneld-bootstrap-v1.json
```

The public Rust entry point is:

```rust
pub fn run(config_path: &Path) -> Result<(), DaemonError>;
```

`DaemonError` is opaque and exposes only
`pub const fn code(self) -> StableCode`.

The production path must match byte-for-byte; aliases containing `.` or `..`,
duplicate separators, relative paths, and alternate paths are rejected.
`test-support` mapped roots exist only in debug/test builds and cannot be
enabled in a release build.

The bootstrap file is canonical compact JSON, at most 64 KiB, with no trailing
newline and exactly these fields in this order:

| Field | Type |
| --- | --- |
| `schema_version` | integer, exactly 1 |
| `platform` | `"linux"` or `"macos"`, exactly matching the binary |
| `release_trust_roots` | array of 1 through 16 trust roots |
| `allowed_release_digest` | one lowercase 64-character SHA-256 hex string |

Each trust root contains, in order:

| Field | Type |
| --- | --- |
| `key_id` | bounded identifier |
| `public_key` | lowercase 64-character raw Ed25519 public-key hex |
| `not_before_unix_ms` | `u64` |
| `not_after_unix_ms` | `u64` |
| `revoked` | Boolean |

Unknown, missing, duplicate, reordered, or differently formatted fields are
rejected because the parsed value must reserialize byte-for-byte to the input.
Trust roots must be sorted and valid under the release verifier. Production
bootstrap directories and files must be root-owned, with directory mode `0755`
and file mode `0444`.

## Strict `kernel-lock.json`

`/etc/savana/kernel-lock.json` is canonical compact JSON, at most 256 KiB,
root-owned, mode `0444`, and contains exactly the following fields in this
order:

| Field | Type |
| --- | --- |
| `schema_version` | `u16`, exactly 1 |
| `protocol_major` | `u16` |
| `minimum_minor` | `u16` |
| `maximum_minor` | `u16` |
| `allowed_release_digests` | array containing exactly the active release digest |
| `release_signature_digest` | lowercase SHA-256 hex |
| `release_target_id` | lowercase SHA-256 hex |
| `source_commit` | exact signed release source commit |
| `installation_profile_digest` | lowercase SHA-256 hex |
| `installation_id` | lowercase SHA-256 hex |
| `platform` | `"linux"` or `"macos"` |
| `daemon_identity` | lock public-key object |
| `daemon_clients` | lock client array |
| `policy_trust_roots` | lock policy-root array |
| `daemon_uid` | `u32` |
| `daemon_gid` | `u32` |
| `jarvis_uid` | `u32` |
| `socket_path` | exact signed absolute path |
| `selected_policy_path` | exact signed absolute path |
| `selected_policy_signature_path` | exact signed absolute path |
| `socket_parent_mode` | `u16`, currently `0750` (`488`) |
| `socket_mode` | `u16`, currently `0660` (`432`) |
| `minimum_policy_version` | `u64` |
| `selected_policy_digest` | lowercase SHA-256 hex |
| `selected_policy_signature_digest` | lowercase SHA-256 hex |
| `selected_policy_version` | `u64` |
| `selected_policy_signing_key_id` | bounded identifier |
| `selected_policy_key_epoch` | `u64` |
| `model_manifest_digest` | lowercase SHA-256 hex |
| `producer_registry_digest` | lowercase SHA-256 hex |
| `ontology_digest` | lowercase SHA-256 hex |
| `approval_key_set_digest` | lowercase SHA-256 hex |
| `resource_profile_digest` | lowercase SHA-256 hex |

The lock public-key object is ordered as `key_id`, `public_key`.

Each lock client is ordered as `client_id`, `key_id`, `public_key`, `role`,
`peer_uid`, `peer_gid`. The only role string is
`"jarvis_kernel_client"`.

Each lock policy root is ordered as `key_id`, `public_key`, `epoch`, `revoked`.

Every lock field is re-derived from and compared with the verified release,
installation profile, selected policy, and selected-policy signature. The lock
does not create authority independently.

## Compiled production paths

Common:

| Artifact | Path |
| --- | --- |
| Bootstrap | `/etc/savana/kerneld-bootstrap-v1.json` |
| Kernel lock | `/etc/savana/kernel-lock.json` |

Linux:

| Artifact | Path |
| --- | --- |
| Release stage | `/opt/savana/kernel/release` |
| Daemon executable | `/opt/savana/kernel/release/bin/savana-kerneld` |
| Daemon seed | `/var/lib/savana/kernel/private/daemon-identity-v1.seed` |
| Policy ledger | `/var/lib/savana/kernel/state/policy-ledger-v1.cbor` |
| Selected policy | `/etc/savana/kernel/selected-policy-v1.cbor` |
| Selected policy signature | `/etc/savana/kernel/selected-policy-v1.sig` |
| Socket | `/run/savana/kernel/kerneld.sock` |

macOS:

| Artifact | Path |
| --- | --- |
| Release stage | `/Library/Application Support/Savana/Kernel/release` |
| Daemon executable | `/Library/Application Support/Savana/Kernel/release/bin/savana-kerneld` |
| Daemon seed | `/Library/Application Support/Savana/Kernel/private/daemon-identity-v1.seed` |
| Policy ledger | `/Library/Application Support/Savana/Kernel/state/policy-ledger-v1.cbor` |
| Selected policy | `/Library/Application Support/Savana/Kernel/selected-policy-v1.cbor` |
| Selected policy signature | `/Library/Application Support/Savana/Kernel/selected-policy-v1.sig` |
| Socket | `/var/run/savana/kernel/kerneld.sock` |

The executable, manifest, signature, signed payloads, bootstrap, lock, selected
policy, selected-policy signature, daemon seed, ledger directory, socket
parent, and socket are verified through descriptor-anchored capabilities and
strict owner/mode/link rules. Path substitution does not create a supported
interface.

## Stable error codes

The CBOR representation of a stable code is its exact uppercase text string:

```text
PROTOCOL_MALFORMED_FRAME
PROTOCOL_TRUNCATED_FRAME
PROTOCOL_FRAME_TOO_LARGE
PROTOCOL_ALLOCATION_REFUSED
PROTOCOL_IO
PROTOCOL_MALFORMED_CBOR
PROTOCOL_NON_CANONICAL_CBOR
PROTOCOL_NESTING_TOO_DEEP
PROTOCOL_UNKNOWN_FIELD
PROTOCOL_UNKNOWN_OPERATION
PROTOCOL_UNSUPPORTED_VERSION
IDENTITY_PEER_REJECTED
IDENTITY_UNKNOWN_CLIENT
IDENTITY_INVALID_SIGNATURE
IDENTITY_TRANSCRIPT_MISMATCH
IDENTITY_REPLAY
IDENTITY_RELEASE_MISMATCH
IDENTITY_KEY_PERMISSIONS
IDENTITY_SOCKET_PERMISSIONS
POLICY_INVALID_SIGNATURE
POLICY_EXPIRED
POLICY_NOT_YET_VALID
POLICY_ROLLBACK
POLICY_EQUIVOCATION
POLICY_LIMIT_EXCEEDED
POLICY_RELEASE_INCOMPATIBLE
DEADLINE_EXCEEDED
KERNEL_OVERLOADED
KERNEL_UNAVAILABLE
ATTESTATION_INVALID_SIGNATURE
ATTESTATION_EXPIRED
ATTESTATION_BINDING_MISMATCH
ONTOLOGY_SEQUENCE_GAP
HANDLE_UNKNOWN
HANDLE_WRONG_CLIENT
HANDLE_WRONG_CONNECTION
HANDLE_WRONG_RUN
HANDLE_WRONG_TYPE
HANDLE_STALE_POLICY
HANDLE_STALE_REGISTRY
HANDLE_ALREADY_CONSUMED
HANDLE_INVALIDATED_BOOT
REGISTRY_INVALID_SIGNATURE
REGISTRY_EQUIVOCATION
ONTOLOGY_INVALID_SIGNATURE
ONTOLOGY_EQUIVOCATION
POLICY_DENIED
APPROVAL_REQUIRED
APPROVAL_INVALID_SIGNATURE
APPROVAL_BINDING_MISMATCH
APPROVAL_REPLAYED
APPROVAL_LEDGER_FULL
```

No diagnostic text, filesystem path, key material, peer identity, transcript,
or internal capability accompanies a stable code on the public Rust error
surface. The exact stable string is also the permanent metric-label value.
This protocol layer does not invent an HTTP status mapping; an outer adapter
may map a code only after it has the authenticated call context.

## Golden vectors

Byte-frozen fixtures and their reproduction instructions live in
`vectors/kerneld/README.md`. `policy-flow-v1.cbor` is a definite CBOR array of
12 byte strings: canonical client requests for tags `10..19`, one canonical
`NeedsApproval` response, and one canonical stable-error response. The server
hello, policy bundle, and release manifest signatures are valid Ed25519
fixtures under their documented test-only public keys.
