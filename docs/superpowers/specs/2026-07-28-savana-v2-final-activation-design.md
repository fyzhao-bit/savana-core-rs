# Savana V2 Final Activation Design

> Date: 2026-07-28
>
> Status: approved for implementation
>
> Extends:
> [Savana Secure Kernel V2](./2026-07-27-savana-secure-kernel-v2-design.md),
> [Savana Kernel V2 Protocol and State Design](./2026-07-27-savana-kernel-v2-protocol-state-design.md),
> and
> [Savana Kernel V2 Deployment Design](./2026-07-27-savana-kernel-v2-deployment-design.md)

## 1. Goal and completion boundary

This slice activates the already implemented Suite-1 cryptographic core as
the only production local service protocol and completes these three
deliverables:

1. publish the fixed V2 service-manager-owned endpoints without a V1 listener,
   protocol probe, or downgrade path;
2. measure and bind the live Linux or macOS peer process and code identity
   before parsing a handshake body; and
3. replace generic operation-body callbacks with exhaustive typed routing for
   all AgentKernel, IngressKernel, and KernelExecutor operations.

Completion of this slice does not by itself claim `PlatformComplete` or
`ProductComplete`. Native keystore/rollback backends, every daemon entry
point outside kerneld and execd, deploy/watchdog, approvalctl, and the complete
two-platform sandbox evidence remain separate gates.

## 2. Final activation mode

The runtime is a final required-mode V2 deployment:

- V1 is not bound, advertised, decoded, probed, or used as fallback.
- A V2 decode failure is never retried with a V1 decoder.
- A V1 prefix sent to a V2 endpoint closes before a CBOR decoder is selected.
- Every edge has a distinct listener identity, client key, server key, role,
  access group, and operation enum.
- A client cannot select or widen its role. The accepted listener or XPC
  service fixes the role before the client sends bytes.
- Every connection performs one Suite-1 handshake, accepts one encrypted
  application request, emits at most one encrypted response, and closes.

The only service edges activated by this slice are:

```text
agentd   → kerneld  AgentKernel
ingressd → kerneld  IngressKernel
kerneld  → execd    KernelExecutor
```

Kerneld must reject `KernelExecutor` as an inbound role. Execd must reject
`AgentKernel` and `IngressKernel` as inbound roles.

## 3. Platform boundary

### 3.1 Isolated native crate

Add one workspace crate named `savana-platform-identity`. This is the only
workspace crate permitted to contain audited `unsafe` blocks. Its
responsibilities are limited to:

- obtaining kernel-authenticated peer credentials or XPC audit tokens;
- pinning the observed process instance while it is measured;
- reading native code-signing and entitlement facts;
- comparing descriptor metadata that only the operating system can supply;
- carrying opaque encrypted frame bytes across XPC without decrypting or
  interpreting application data; and
- returning a closed, owned measurement result.

It must not depend on policy-core, vault, input-runtime, agentd, ingressd,
approvald, execd runtime state, or kerneld. It must not receive a service
private key, decrypt a Suite-1 record, decode operation CBOR, read a vault, or
construct an opaque application handle.

Every other workspace crate continues to inherit
`unsafe_code = "forbid"`. The platform crate uses
`unsafe_code = "deny"` at crate scope and narrow
`#[allow(unsafe_code)]` only on the FFI functions whose safety contracts are
documented next to the call.

Its public result is a non-exhaustive closed enum:

```rust
pub enum NativePeerMeasurementV2 {
    Linux {
        uid: u32,
        gid: u32,
        pid: u32,
        process_start_time: u64,
        executable_measurement: [u8; 32],
    },
    MacOs {
        audit_token: [u8; 32],
        euid: u32,
        egid: u32,
        bundle_id: BoundedIdentityStringV2,
        team_id: BoundedIdentityStringV2,
        code_directory_measurement: [u8; 32],
        designated_requirement_measurement: [u8; 32],
        entitlement_measurement: [u8; 32],
    },
}
```

The enum implements redacted `Debug`. Identifier strings are nonempty,
ASCII-only, and at most 255 bytes. No path, command line, environment,
entitlement value, raw Security.framework object, file descriptor, audit
token pointer, or process handle escapes the measurement object.

### 3.2 Linux measurement

Linux production endpoints are socket-activated descriptors:

```text
/run/savana/kerneld/agentd/kerneld.sock
/run/savana/kerneld/ingressd/kerneld.sock
/run/savana/execd/kerneld/execd.sock
```

The service manager supplies the listening descriptors. Production code never
falls back to `bind(2)` using a configured or caller-selected path.

For each accepted connection, before a handshake body is decoded:

1. read `SO_PEERCRED` once and reject PID zero;
2. create a `pidfd` for that PID and reject an already exited process;
3. open a descriptor-anchored `/proc/<pid>` directory;
4. parse field 22 of `/proc/<pid>/stat` as the nonzero process start time;
5. open `/proc/<pid>/exe` through the held proc directory, require a regular
   single-link executable owned and protected as required by the active
   manifest, and SHA-256 all executable bytes from that descriptor;
6. compare PID-instance liveness, UID, GID, start time, executable digest, and
   edge role with the active edge lock; and
7. poll the pidfd once more immediately before accepting the measurement.

The held pidfd and executable descriptor prevent PID reuse and pathname
replacement from changing which process or executable was measured. A short
read, procfs race, process exit, digest mismatch, unsafe executable metadata,
or unavailable pidfd fails closed.

### 3.3 macOS measurement and transport

Production macOS uses these distinct launchd Mach/XPC services:

```text
group.com.savana.agent-kernel.kerneld
group.com.savana.ingress-kernel.kerneld
group.com.savana.kernel-execd.execd
```

The platform crate obtains the connection audit token from XPC and derives the
PID, EUID, and EGID from that token. It calls Security.framework using the
audit token as the guest identity, then verifies:

- the exact active designated requirement;
- Bundle ID and Team ID;
- active CodeDirectory identity;
- the closed entitlement projection; and
- the manifest's XPC service and role lock.

The fixed 32-byte CodeDirectory measurement is:

```text
SHA256(
  "SAVANA_MACOS_CODE_DIRECTORY_MEASUREMENT_V2\0" ||
  security_framework_unique_code_identity_bytes
)
```

The designated-requirement and entitlement measurements use distinct domains:

```text
"SAVANA_MACOS_DESIGNATED_REQUIREMENT_MEASUREMENT_V2\0"
"SAVANA_MACOS_ENTITLEMENT_MEASUREMENT_V2\0"
```

Their inputs are the exact canonical bytes locked by the signed deployment
manifest. A valid Apple signature that does not match those locked values is
rejected.

The XPC adapter transports only bounded encrypted handshake/record frame byte
strings. It does not expose an application request to the platform crate. A
connection sends the exact Suite-1 frame sequence and is invalidated after
the response or any error.

## 4. Edge locks and startup inputs

The signed V2 deployment manifest gains a closed edge-lock table. Each entry
binds:

```text
edge ID
server service ID
client service ID
EndpointRoleV2
listener/XPC identity digest
listener owner/group/mode or Mach service identity
expected client UID/GID or EUID/EGID
expected executable/CodeDirectory measurement
designated-requirement measurement where applicable
entitlement measurement where applicable
client handshake key ID
server handshake key ID
active protocol ABI digest
```

Exactly one entry must exist for each of the three edges in section 2, in
canonical edge-ID order. Missing, duplicate, cross-role, cross-key, or
cross-service entries make startup fail before readiness.

Linux verifies the socket descriptor's type, accepting state, inode, device,
owner, group, mode, and canonical path against its edge lock. macOS verifies
the launchd service identity and entitlement lock. Test-only constructors may
accept owned `UnixListener` or XPC fakes, but no test override is compiled
into a release build.

## 5. Transport integration

Refactor the Suite-1 connection server over a private bounded frame-channel
trait:

```rust
trait V2FrameChannel {
    fn read_handshake_frame(&mut self, deadline: Instant) -> Result<Vec<u8>, ChannelErrorV2>;
    fn write_handshake_frame(&mut self, frame: &[u8], deadline: Instant)
        -> Result<(), ChannelErrorV2>;
    fn read_record_frame(&mut self, deadline: Instant) -> Result<Vec<u8>, ChannelErrorV2>;
    fn write_record_frame(&mut self, frame: &[u8], deadline: Instant)
        -> Result<(), ChannelErrorV2>;
    fn close(&mut self);
}
```

Linux implements this trait with an owned Unix stream. macOS implements it
with the opaque encrypted-byte XPC adapter. Each method enforces the existing
compiled framing limits before allocation and one absolute connection
deadline.

The listener worker receives an already verified tuple:

```text
fixed endpoint role
verified native peer measurement
active edge lock
policy-generation lease
owned channel
```

Only after all tuple components agree may it ask the handshake owner to
consume `ClientHello`.

## 6. Typed operation ABI

The generic public shape
`KernelServiceOperationV2 { role, tag, canonical_body }` is no longer an
authority-bearing dispatcher input. The protocol crate exposes three closed
typed operation enums:

```rust
pub enum KernelAgentOperationV2 { /* tag 0 and 20..=43 */ }
pub enum KernelIngressOperationV2 { /* tag 0 and 40..=50 */ }
pub enum ExecutorOperationV2 { /* tag 0 and 60..=63 */ }
```

The exact variants are:

```text
KernelAgentOperationV2
0  Health
20 ClaimAgentSession
21 PrepareFollowupIngress
22 GetAgentSessionStatus
23 PreparePlannerCall
24 CommitPlannerValue
25 DeriveValue
26 ProposeToolCall
27 EvaluateToolCall
28 AuthorizeToolCall
29 DispatchExecution
30 GetExecutionStatus
31 ReadAgentView
32 PrepareRelease
33 AuthorizeRelease
34 DispatchRelease
35 GetReleaseStatus
36 RevokeVault
37 CloseAgentSession
38 PrepareNewIngress
39 PrepareAgentUiAuthentication
40 AuthenticateAgentUi
41 GetKernelTaskStatus
42 CancelKernelTask
43 ResumeCommittedAgentAuthentication

KernelIngressOperationV2
0  Health
40 BeginInput
41 AppendInputChunk
42 FinalizeInput
43 CommitInputSettlement
44 AbortInput
45 GetInputStatus
46 PrepareIngressUiAuthentication
47 AuthenticateIngressUi
48 RegisterParserWorkerJob
49 AppendParserWorkerPageFrame
50 CommitParserWorkerResult

ExecutorOperationV2
0  Health
60 Dispatch
61 QueryByExecutionNonce
62 AcknowledgeCommittedCompletion
63 FetchCompletion
```

Every variant owns its exact request type. Every success response is a
role-specific typed response enum. Request and response encoders preserve the
already frozen numeric tags and canonical-CBOR rules.

The decoder first peeks only at version, role, request ID, deadline, and tag.
Those routing values must match the authenticated record and listener role.
It then selects exactly one role-specific decoder and exactly one
operation-specific body schema. Unknown tags, trailing bytes, noncanonical
forms, wrong field counts, and cross-role tags close the connection.

External requests may contain opaque handles and signed evidence defined by
the protocol. They may not contain an in-process capability, store reference,
file descriptor, signing key, state-owner sender, or caller-selected service
identity.

## 7. Runtime ownership and routing

### 7.1 Kerneld

Replace the generic handler closure in `KernelServiceDispatcherV2` with a
`KernelRuntimeOwnerV2`. It is the only owner of mutable kernel V2 state:

- agent sessions, tasks, runs, correlations, replay records, and opaque-handle
  resolver tables;
- ingress acceptance state and the durable vault;
- G1/G2 input runtime and G3 provenance;
- G4 policy/registry/ontology state and action-intent deduplication;
- G5 validator dispatch state;
- G6 consumed approval and authentication settlements;
- G7 dispatch, release, reconciliation, and execution-status state;
- policy WAL, active generation lease state, and recovery projections.

The owner accepts only:

```rust
enum KernelRuntimeCommandV2 {
    Agent(AuthenticatedKernelAgentCommandV2),
    Ingress(AuthenticatedKernelIngressCommandV2),
}
```

The outer enums and every inner operation match are exhaustive. No default
arm, numeric range arm, plugin callback, or general `FnMut` handler is used.

### 7.2 Execd

`KernelExecutor` is served only by execd. Its listener routes the typed
`ExecutorOperationV2` to `ExecdStateOwnerV2`:

- tag 60 verifies and durably accepts the exact signed dispatch envelope;
- tag 61 queries by the durable execution nonce;
- tag 62 commits the acknowledgement/tombstone transition; and
- tag 63 returns the retained completion allowed by current durable state.

The executor owner retains the effect gate, journal, credentials, and worker
supervisor. Kerneld receives only typed status, receipt, and bounded completion
projections.

### 7.3 Policy-generation lease

The listener acquires a lease from the active verified deployment before it
begins an application request. The lease binds:

```text
active_state_manifest_digest
deployment_generation
protocol ABI digest
effect-fence epoch
endpoint edge lock
```

The worker keeps the lease until the encrypted response is written or the
channel closes. The state owner rechecks the same generation and effect-fence
epoch immediately before every mutation. Rollover stops new leases, waits for
bounded readers, reconciles unresolved durable effects, and then publishes
the new listener generation. An old connection cannot mutate new-generation
state.

## 8. Error and fail-stop rules

Failures before authenticated application routing produce no application
response. This includes listener identity, native peer measurement, handshake,
role, record metadata, replay, request-ID, operation-tag, and canonical-body
failures.

An authenticated well-formed operation may return only the public stable
codes allowed by that operation's frozen error set. Internal errors are mapped
inside the state owner; the transport never serializes an unrestricted
`StableCode`.

These conditions trigger fail-stop rather than a recoverable response:

- owner-thread panic or poison;
- rollback-anchor mismatch;
- authenticated durable-state corruption;
- audit durability failure for a required mutation;
- an unresolved effect whose state cannot be classified safely; or
- generation/effect-fence inconsistency.

Shutdown closes listeners first, then drains bounded non-effect work, performs
required reconciliation, stops owner threads, closes platform channels, and
zeroizes connection/session material.

## 9. Startup gate

The final startup order is:

1. verify signed deployment manifest, protocol lock, and selected policy;
2. open platform keystore handles, rollback anchors, vault/WAL, audit sink,
   and EffectGate;
3. construct state owners and run recovery/reconciliation;
4. receive all service-manager listener or XPC endpoints;
5. verify this process, every endpoint, and every edge lock;
6. start the kerneld and execd V2 accept loops; and
7. publish readiness only after every required endpoint is accepting.

Any failure unwinds in reverse order. No listener remains published and no V1
endpoint is created. Release builds have no synthetic identity, in-memory
rollback, test key, caller-selected socket, or permissive manifest path.

## 10. Verification

The implementation must provide:

- hand-authored golden request and success-response vectors for all 42
  operations;
- one invalid-field, unknown-field, noncanonical, and wrong-role vector for
  every operation family;
- proof that every numeric tag reaches exactly one typed handler;
- proof that kerneld rejects inbound `KernelExecutor` and execd rejects
  `AgentKernel`/`IngressKernel`;
- real encrypted connection tests for AgentKernel, IngressKernel, and
  KernelExecutor;
- at least one encrypted end-to-end path through each G1 through G7 gate;
- duplicate, replay, expired-deadline, stale-generation, and second-request
  rejection;
- crash-point and restart tests around every effect-start/commit boundary;
- Linux tests for PID reuse, process exit, executable replacement, unsafe
  metadata, wrong UID/GID, and wrong socket descriptor;
- macOS tests for wrong audit token, Team ID, Bundle ID, CodeDirectory,
  designated requirement, entitlement projection, and Mach service;
- absence of the V1 production listener and rejection of V1 bytes; and
- full workspace format, Clippy with `-D warnings`, documentation, and test
  verification.

Platform-specific native tests run on their native operating system. A build
or test on only one operating system is reported as single-platform evidence,
not two-platform completion.

## 11. Documentation claims

README may state that these three deliverables are complete only after the
verification in section 10 passes. It must continue to list every remaining
platform/product gate and must not claim `PlatformComplete` or
`ProductComplete` solely because V2 endpoints are active.
