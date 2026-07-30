# Savana V2 Final Activation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Suite-1 V2 the only production service protocol, authenticate live Linux/macOS code identity before handshake decoding, and route all 42 kernel/executor operations through closed typed state owners.

**Architecture:** Protocol-owned DTO modules define exhaustive AgentKernel, IngressKernel, and KernelExecutor request/response enums. A small audited native crate measures peers and adapts Linux UDS or macOS XPC into bounded encrypted-frame channels. Kerneld and execd accept only service-manager endpoints, acquire generation leases, and submit typed commands to their existing single-owner runtimes.

**Tech Stack:** Rust 1.82, canonical CBOR with `minicbor`, Suite-1 X25519/Ed25519/HKDF/ChaCha20-Poly1305, `nix`/`rustix`, Linux `SO_PEERCRED`/pidfd/procfs, macOS XPC/CoreFoundation/Security.framework FFI, bounded `sync_channel` owners.

## Global Constraints

- Final mode publishes V2 only; it contains no V1 listener, probe, decoder fallback, or downgrade.
- Linux uses the three fixed systemd-owned socket paths from the approved design.
- macOS uses the three fixed launchd Mach/XPC service names from the approved design.
- Role is fixed by the accepted endpoint before any client bytes are decoded.
- Every connection performs one handshake, one encrypted request, at most one encrypted response, then closes.
- `savana-platform-identity` is the only crate allowed narrow documented `unsafe` FFI; every other crate keeps `unsafe_code = "forbid"`.
- Original data, G1-G7 state, vault material, private keys, and in-process capabilities stay outside the platform crate.
- Every operation body is operation-specific and canonical; unrestricted canonical byte blobs are not dispatcher authority.
- Every state mutation executes on the appropriate bounded owner thread under an active generation/effect-fence lease.
- Identity/canonical/role/record failures close silently; well-formed authenticated operations expose only their frozen public error set.
- Rust production behavior is added test-first and the focused test must be observed failing for the intended reason before implementation.

---

### Task 1: Protocol-owned opaque handles and bounded wire primitives

**Files:**
- Modify: `crates/savana-kernel-protocol/src/v2/handles.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/primitives.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/mod.rs`
- Create: `crates/savana-kernel-protocol/tests/v2_kernel_handles.rs`

**Interfaces:**
- Consumes: `V2DecodeContext`, canonical fixed-byte encoders, and the exhaustive handle registry in protocol-state design section 3.2.
- Produces: all AgentKernel/IngressKernel wire handle types, `ArgumentNameV2`, `BoundedIdentityStringV2`, and bounded canonical byte/vector helpers used by Tasks 2-4.

- [x] **Step 1: Write failing handle separation and redaction tests**

  Add compile/runtime tests using the concrete API:

  ```rust
  let session = AgentSessionHandleV2::from_token([7; 32]).unwrap();
  let encoded = encode_typed_v2(&session).unwrap();
  assert_eq!(encoded, [0x58, 0x20].into_iter().chain([7; 32]).collect::<Vec<_>>());
  assert_eq!(format!("{session:?}"), "AgentSessionHandleV2(<redacted>)");
  assert!(decode_typed_v2::<RunHandleV2>(&encoded).is_ok());
  assert_ne!(
      AgentSessionHandleV2::TYPE_DOMAIN,
      RunHandleV2::TYPE_DOMAIN,
  );
  assert!(AgentSessionHandleV2::from_token([0; 32]).is_err());
  ```

  The wire token is intentionally the same fixed 32 bytes for each type; type
  confusion is prevented by the typed decoder and resolver domain, not by
  changing wire bytes.

- [x] **Step 2: Run the focused test and verify RED**

  Run:
  `cargo test -p savana-kernel-protocol --test v2_kernel_handles --all-features`

  Expected: compilation fails because `AgentSessionHandleV2`,
  `RunHandleV2`, and the typed test codec do not exist.

- [x] **Step 3: Implement the closed handle macro**

  Add a private macro that emits a nonzero 32-byte token, redacted `Debug`,
  exact CBOR byte-string encoding, exact-length decoding, and an exact
  `TYPE_DOMAIN`:

  ```rust
  opaque_handle_v2!(
      AgentSessionHandleV2,
      b"SAVANA_AGENT_SESSION_HANDLE_V2\0"
  );
  opaque_handle_v2!(RunHandleV2, b"SAVANA_RUN_HANDLE_V2\0");
  opaque_handle_v2!(ValueHandleV2, b"SAVANA_VALUE_HANDLE_V2\0");
  ```

  Instantiate it for every kerneld-owned handle named in sections 5.2-5.4:
  new-task/UI-auth preparation, ingress bootstrap, ingress/agent
  authorization, input writer/session/parser/pending, agent session, run,
  value, document, step, planner ticket, tool, intent, pending tool,
  ingress/tool/release approval, execution ticket/execution, pending
  release/release ticket/release, and agent-view cursor.

- [x] **Step 4: Implement bounded scalar helpers**

  Add:

  ```rust
  pub struct ArgumentNameV2(String);             // 1..=128 UTF-8 bytes
  pub struct BoundedIdentityStringV2(String);    // 1..=255 ASCII bytes
  pub struct ZeroizingBytesV2(Zeroizing<Vec<u8>>); // 0..=8 MiB
  ```

  Constructors validate before allocation where possible. `ZeroizingBytesV2`
  has redacted `Debug`, is not `Clone`, and encodes as one definite byte
  string. Add shared `decode_bounded_vec_v2<T, const N: usize>` and
  sorted/duplicate rejection helpers without exposing an unbounded public
  collection constructor.

- [x] **Step 5: Run focused and protocol tests**

  Run:
  `cargo test -p savana-kernel-protocol --test v2_kernel_handles --all-features`
  and `cargo test -p savana-kernel-protocol --all-targets --all-features`.

  Expected: all protocol tests pass and opaque `Debug` output contains no
  token bytes.

- [x] **Step 6: Preserve Task 1 in the isolated worktree**

  The pre-existing V2 baseline is intentionally uncommitted and includes
  `v2/mod.rs` plus its referenced modules. Keep this task in the isolated
  worktree rather than create a commit that cannot build from its parent.

---

### Task 2: Typed AgentKernel wire ABI

**Files:**
- Create: `crates/savana-kernel-protocol/src/v2/kernel_agent.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/mod.rs`
- Create: `crates/savana-kernel-protocol/tests/v2_kernel_agent_wire.rs`

**Interfaces:**
- Consumes: Task 1 handles/primitives and the exact DTO blocks in protocol-state design section 5.2.
- Produces: `KernelAgentOperationV2`, `KernelAgentSuccessV2`, and exact operation-body encode/decode functions for tags `0, 20..=43`.

- [ ] **Step 1: Write failing exhaustive tag tests**

  Construct one valid minimal request per variant and assert this exact tag
  list:

  ```rust
  assert_eq!(
      kernel_agent_operation_tags_v2(),
      &[0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43]
  );
  ```

  For each encoded operation, decode and re-encode byte-for-byte. Mutate its
  array length, tag, one handle length, and add trailing bytes; each mutation
  must fail.

- [ ] **Step 2: Run the focused test and verify RED**

  Run:
  `cargo test -p savana-kernel-protocol --test v2_kernel_agent_wire --all-features`

  Expected: compilation fails because `KernelAgentOperationV2` does not exist.

- [ ] **Step 3: Implement the 25 request variants**

  Define the exact enum:

  ```rust
  pub enum KernelAgentOperationV2 {
      Health(KernelAgentHealthRequestV2),
      ClaimAgentSession(ClaimAgentSessionRequestV2),
      PrepareFollowupIngress(PrepareFollowupIngressRequestV2),
      GetAgentSessionStatus(GetAgentSessionStatusRequestV2),
      PreparePlannerCall(PreparePlannerCallRequestV2),
      CommitPlannerValue(CommitPlannerValueRequestV2),
      DeriveValue(DeriveValueRequestV2),
      ProposeToolCall(ProposeToolCallRequestV2),
      EvaluateToolCall(EvaluateToolCallRequestV2),
      AuthorizeToolCall(AuthorizeToolCallRequestV2),
      DispatchExecution(DispatchExecutionRequestV2),
      GetExecutionStatus(GetExecutionStatusRequestV2),
      ReadAgentView(ReadAgentViewRequestV2),
      PrepareRelease(PrepareReleaseRequestV2),
      AuthorizeRelease(AuthorizeReleaseRequestV2),
      DispatchRelease(DispatchReleaseRequestV2),
      GetReleaseStatus(GetReleaseStatusRequestV2),
      RevokeVault(RevokeVaultRequestV2),
      CloseAgentSession(CloseAgentSessionRequestV2),
      PrepareNewIngress(PrepareNewIngressRequestV2),
      PrepareAgentUiAuthentication(PrepareAgentUiAuthenticationRequestV2),
      AuthenticateAgentUi(AuthenticateAgentUiRequestV2),
      GetKernelTaskStatus(GetKernelTaskStatusRequestV2),
      CancelKernelTask(CancelKernelTaskRequestV2),
      ResumeCommittedAgentAuthentication(
          ResumeCommittedAgentAuthenticationRequestV2
      ),
  }
  ```

  Implement every request field and bound exactly as written in section 5.2.
  Protocol-owned signed DTOs use `[payload_bstr, key_id, signature]` and
  validate their internal canonical payload before construction.

- [ ] **Step 4: Implement typed success responses**

  Add `KernelAgentSuccessV2` with the same tag paired to each exact response
  type from section 5.2. The response decoder receives the expected request
  tag and rejects any other success variant. Enforce 256 prompt values,
  evidence values, plan steps, and named arguments; enforce 4096 active tools;
  enforce nonzero deadlines, generations, nonces, IDs, and handles.

- [ ] **Step 5: Add hand-authored golden vectors**

  Hand-author at least the unit health vector and one request from each error
  class: ClaimAgentSession, PreparePlannerCall, DispatchExecution,
  ReadAgentView, and CancelKernelTask. Do not generate the expected bytes with
  the production encoder.

- [ ] **Step 6: Run focused and protocol tests**

  Run:
  `cargo test -p savana-kernel-protocol --test v2_kernel_agent_wire --all-features`
  and `cargo test -p savana-kernel-protocol --all-targets --all-features`.

  Expected: all 25 tags round-trip canonically and every negative vector fails.

- [ ] **Step 7: Commit Task 2**

  ```bash
  git add crates/savana-kernel-protocol/src/v2/kernel_agent.rs \
          crates/savana-kernel-protocol/src/v2/mod.rs \
          crates/savana-kernel-protocol/tests/v2_kernel_agent_wire.rs
  git commit -m "feat(protocol): define typed agent kernel operations"
  ```

---

### Task 3: Typed IngressKernel wire ABI

**Files:**
- Create: `crates/savana-kernel-protocol/src/v2/kernel_ingress.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/mod.rs`
- Create: `crates/savana-kernel-protocol/tests/v2_kernel_ingress_wire.rs`

**Interfaces:**
- Consumes: Task 1 primitives and protocol-state design section 5.3.
- Produces: `KernelIngressOperationV2`, `KernelIngressSuccessV2`, and codecs for tags `0, 40..=50`.

- [ ] **Step 1: Write failing exhaustive and channel-confusion tests**

  Assert the exact tags `[0, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50]`.
  Hand-author BeginInput and AppendInputChunk vectors. Prove a direct append
  cannot encode `ExtractedPage`, channel commitments are strictly sorted with
  no duplicates, and chunks above 8 MiB are rejected before allocation.

- [ ] **Step 2: Run the focused test and verify RED**

  Run:
  `cargo test -p savana-kernel-protocol --test v2_kernel_ingress_wire --all-features`

  Expected: compilation fails because `KernelIngressOperationV2` is absent.

- [ ] **Step 3: Implement request and response enums**

  Implement the exact request/response structures from section 5.3 and:

  ```rust
  pub enum KernelIngressOperationV2 {
      Health(KernelIngressHealthRequestV2),
      BeginInput(BeginInputRequestV2),
      AppendInputChunk(AppendInputChunkRequestV2),
      FinalizeInput(FinalizeInputRequestV2),
      CommitInputSettlement(CommitInputSettlementRequestV2),
      AbortInput(AbortInputRequestV2),
      GetInputStatus(GetInputStatusRequestV2),
      PrepareIngressUiAuthentication(
          PrepareIngressUiAuthenticationRequestV2
      ),
      AuthenticateIngressUi(AuthenticateIngressUiRequestV2),
      RegisterParserWorkerJob(RegisterParserWorkerJobRequestV2),
      AppendParserWorkerPageFrame(AppendParserWorkerPageFrameRequestV2),
      CommitParserWorkerResult(CommitParserWorkerResultRequestV2),
  }
  ```

  Encode every enum as `[tag_u16, body]`. Re-encode equality is mandatory.
  `DirectInputChannelV2` has only OriginalSource and ChatText.

- [ ] **Step 4: Run focused and protocol tests**

  Run the focused test and then all protocol targets. Expected: all pass.

- [ ] **Step 5: Commit Task 3**

  ```bash
  git add crates/savana-kernel-protocol/src/v2/kernel_ingress.rs \
          crates/savana-kernel-protocol/src/v2/mod.rs \
          crates/savana-kernel-protocol/tests/v2_kernel_ingress_wire.rs
  git commit -m "feat(protocol): define typed ingress kernel operations"
  ```

---

### Task 4: Typed KernelExecutor wire ABI and application envelope

**Files:**
- Create: `crates/savana-kernel-protocol/src/v2/executor.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/application.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/kernel_service.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/mod.rs`
- Create: `crates/savana-kernel-protocol/tests/v2_executor_wire.rs`
- Modify: `crates/savana-kernel-protocol/tests/v2_transport.rs`

**Interfaces:**
- Consumes: Tasks 1-3 typed operations and protocol-state design section 5.4.
- Produces: `ExecutorOperationV2`, `ExecutorSuccessV2`, `KernelServiceOperationV2` as a closed enum of the three role enums, and exact typed application envelopes.

- [ ] **Step 1: Write failing executor and cross-role tests**

  Assert exact executor tags `[0, 60, 61, 62, 63]`. Hand-author Dispatch and
  Query vectors. Prove an AgentKernel tag/body is rejected under
  KernelExecutor and an executor tag is rejected under both kerneld roles.

- [ ] **Step 2: Run focused tests and verify RED**

  Run:
  `cargo test -p savana-kernel-protocol --test v2_executor_wire --all-features`

  Expected: compilation fails because `ExecutorOperationV2` is absent.

- [ ] **Step 3: Implement executor request/response types**

  Implement section 5.4 exactly, including the paired-option invariant for
  `Indeterminate`, bounded zeroizing completion payloads, descriptor/payload
  kind agreement, and exact nonce/core/subject fields.

- [ ] **Step 4: Close the service operation enum**

  Replace the generic role/tag/body authority with:

  ```rust
  pub enum KernelServiceOperationV2 {
      Agent(KernelAgentOperationV2),
      Ingress(KernelIngressOperationV2),
      Executor(ExecutorOperationV2),
  }
  ```

  Keep `role()`, `tag()`, and canonical body encoding as derived accessors.
  Remove public construction from arbitrary canonical bytes. Application
  decode selects the variant from the already authenticated role and tag.

- [ ] **Step 5: Run protocol regression tests**

  Run all protocol targets. Expected: typed Suite-1 tests pass; arbitrary
  canonical body construction no longer compiles at dispatcher call sites.

- [ ] **Step 6: Commit Task 4**

  ```bash
  git add crates/savana-kernel-protocol/src/v2/executor.rs \
          crates/savana-kernel-protocol/src/v2/application.rs \
          crates/savana-kernel-protocol/src/v2/kernel_service.rs \
          crates/savana-kernel-protocol/src/v2/mod.rs \
          crates/savana-kernel-protocol/tests/v2_executor_wire.rs \
          crates/savana-kernel-protocol/tests/v2_transport.rs
  git commit -m "feat(protocol): close v2 kernel operation families"
  ```

---

### Task 5: Audited native identity crate

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/savana-platform-identity/Cargo.toml`
- Create: `crates/savana-platform-identity/src/lib.rs`
- Create: `crates/savana-platform-identity/src/linux.rs`
- Create: `crates/savana-platform-identity/src/macos.rs`
- Create: `crates/savana-platform-identity/src/macos/ffi.rs`
- Create: `crates/savana-platform-identity/tests/native_peer.rs`

**Interfaces:**
- Consumes: an accepted OS channel and an immutable `ExpectedNativePeerV2`.
- Produces: `NativePeerMeasurementV2`, redacted `BoundedIdentityStringV2`, Linux stream measurement, and macOS audit-token code measurement.

- [ ] **Step 1: Write failing platform-neutral validation tests**

  Test nonzero PID/start time/digests, identifier bounds, redacted Debug, and
  exact expected/observed comparison. The comparison must reject one-field
  changes for UID, GID, role identity, executable/CodeDirectory, requirement,
  and entitlements.

- [ ] **Step 2: Write the native failing test**

  On Linux, use `UnixStream::pair` and expect current PID/UID/GID plus the
  SHA-256 of `/proc/self/exe`. On macOS, use a test-only audit-token fixture
  parser and Security.framework measurement of the current signed test
  process when available; unsigned test binaries must return the closed
  `CodeIdentityUnavailable` error rather than synthesize an identity.

- [ ] **Step 3: Run and verify RED**

  Run:
  `cargo test -p savana-platform-identity --all-targets`

  Expected: package or APIs do not exist.

- [ ] **Step 4: Implement Linux pin-and-measure**

  Use safe `nix`/`rustix` APIs for `SO_PEERCRED`, pidfd, proc directory/file
  descriptors, metadata, polling, and SHA-256 reads. Parse `/proc/<pid>/stat`
  by locating the final `)` before fields 3-22 so spaces/parentheses in
  `comm` cannot shift the start-time field. Hold pidfd/proc/exe descriptors
  until comparison completes.

- [ ] **Step 5: Implement macOS FFI measurement**

  Keep all raw pointers and ownership in `macos/ffi.rs`. Document and test the
  retain/release contract for every CoreFoundation/Security object. Use the
  XPC audit token as the guest attribute, call
  `SecCodeCopyGuestWithAttributes`, `SecCodeCheckValidity`, and
  `SecCodeCopySigningInformation`, then copy only bounded owned values into
  `NativePeerMeasurementV2`. Hash CodeDirectory unique bytes, canonical
  designated requirement, and canonical closed entitlement projection under
  the three approved domains.

- [ ] **Step 6: Verify unsafe containment**

  Add a workspace test that scans Rust sources: unsafe tokens are permitted
  only in `crates/savana-platform-identity/src/macos/ffi.rs`; every other
  crate must retain `#![forbid(unsafe_code)]` or workspace lint inheritance.

- [ ] **Step 7: Run tests and commit**

  Run the platform crate, workspace-boundary test, and Clippy for the new
  crate. Then commit:

  ```bash
  git add Cargo.toml Cargo.lock crates/savana-platform-identity \
          crates/savana-kernel-protocol/tests/workspace_boundary.rs
  git commit -m "feat(platform): measure native v2 peer identity"
  ```

---

### Task 6: Signed edge locks and generation leases

**Files:**
- Modify: `crates/savana-kerneld/src/deployment_trust.rs`
- Create: `crates/savana-kerneld/src/v2_edge.rs`
- Modify: `crates/savana-kerneld/src/policy_runtime.rs`
- Modify: `crates/savana-kerneld/src/lib.rs`

**Interfaces:**
- Consumes: verified deployment manifest and native measurements from Task 5.
- Produces: `VerifiedServiceEdgeV2`, fixed-role `VerifiedAcceptedPeerV2`, and `V2GenerationLease`.

- [ ] **Step 1: Write failing edge-table tests**

  Encode exactly three canonical edge locks in AgentKernel,
  IngressKernel, KernelExecutor order. Reject missing/duplicate/reordered
  locks, swapped client/server identities, key reuse, role swap, wrong socket
  or Mach identity, wrong protocol ABI, and stale fence epoch.

- [ ] **Step 2: Run and verify RED**

  Run:
  `cargo test -p savana-kerneld v2_edge --all-features`

  Expected: `VerifiedServiceEdgeV2` does not exist.

- [ ] **Step 3: Implement edge verification**

  Make edge construction possible only from a verified manifest. Conversion
  from `NativePeerMeasurementV2` compares every platform field and yields a
  fixed role plus `PeerIdentityBindingV2`; callers cannot pass a role.

- [ ] **Step 4: Implement generation leasing**

  Add `PolicyRuntime::acquire_v2_generation_lease(edge, deadline)`. The RAII
  lease contains only manifest/generation/ABI/fence/edge digests, increments
  the existing rollover reader count, and releases it on drop. Mutations call
  `lease.revalidate(&active_snapshot)` on the owner thread.

- [ ] **Step 5: Run kerneld tests and commit**

  Run all kerneld targets and commit the four files with
  `feat(kerneld): bind v2 edges to generation leases`.

---

### Task 7: Bounded frame channels and final listeners

**Files:**
- Create: `crates/savana-kerneld/src/v2_channel.rs`
- Create: `crates/savana-kerneld/src/v2_listener.rs`
- Modify: `crates/savana-kerneld/src/v2_connection.rs`
- Modify: `crates/savana-kerneld/src/server.rs`
- Modify: `crates/savana-kerneld/src/bootstrap.rs`
- Modify: `crates/savana-kerneld/src/lib.rs`
- Create: `crates/savana-execd/src/v2_listener.rs`
- Create: `crates/savana-execd/src/main.rs`
- Modify: `crates/savana-execd/src/lib.rs`

**Interfaces:**
- Consumes: Tasks 4-6 typed operations, edge verification, native measurement, generation lease, handshake owners.
- Produces: Linux service-manager UDS accept loops, macOS XPC frame adapters, and V2-only kerneld/execd startup.

- [ ] **Step 1: Write failing endpoint/role tests**

  Pass real `UnixListener` descriptors under test support. Prove AgentKernel
  works only on the agent endpoint, IngressKernel only on ingress, and
  KernelExecutor only on execd. Send V1 frame prefixes and prove no V1
  response/decoder invocation. Prove a second request reaches EOF.

- [ ] **Step 2: Run and verify RED**

  Run focused listener tests. Expected: V2 listener constructors are absent.

- [ ] **Step 3: Extract `V2FrameChannel`**

  Move bounded frame reads/writes from `v2_connection.rs` behind the private
  trait frozen in the design. Implement `UnixV2FrameChannel` without changing
  frame bytes. Implement the macOS XPC adapter in the platform crate as
  opaque byte messages; no plaintext or protocol type crosses that crate.

- [ ] **Step 4: Implement service-manager endpoint intake**

  Linux accepts only the exact inherited descriptor count and names. Verify
  listener type, accepting state, inode/device, UID/GID/mode, and path against
  the edge lock. macOS accepts only the exact launchd service name and audit
  token flow. Release builds have no bind-by-path fallback.

- [ ] **Step 5: Activate final startup**

  Kerneld starts only AgentKernel and IngressKernel servers. Execd starts only
  KernelExecutor. Remove the V1 server from the production `run` path and keep
  it available only under `test-support` for frozen V1 regression tests.
  Readiness follows successful recovery and activation of all required V2
  endpoints.

- [ ] **Step 6: Run listener, CLI, and regression tests**

  Run kerneld/execd targets and existing V1 protocol fixture tests. Expected:
  V1 wire fixtures remain stable as library compatibility evidence, while no
  production listener serves them.

- [ ] **Step 7: Commit Task 7**

  Commit with `feat(runtime): activate role-isolated v2 listeners`.

---

### Task 8: Exhaustive kerneld typed runtime owner

**Files:**
- Create: `crates/savana-kerneld/src/v2_kernel_owner.rs`
- Modify: `crates/savana-kerneld/src/v2_dispatch.rs`
- Modify: `crates/savana-kerneld/src/v2_runtime.rs`
- Modify: `crates/savana-kerneld/src/v2_recovery.rs`
- Modify: `crates/savana-kerneld/src/lib.rs`

**Interfaces:**
- Consumes: typed AgentKernel/IngressKernel operations, active policy/vault/runtime services, and `V2GenerationLease`.
- Produces: `KernelRuntimeOwnerV2::dispatch_agent` and `dispatch_ingress`, exhaustive typed success/error results, and no generic handler closure.

- [ ] **Step 1: Write failing exhaustive handler coverage test**

  Construct every operation variant with a valid fixture and record the exact
  typed handler discriminant. Assert all 37 kerneld tags are covered once.
  Prove `KernelExecutor` has no kerneld dispatch entry.

- [ ] **Step 2: Run and verify RED**

  Run:
  `cargo test -p savana-kerneld v2_kernel_owner --all-features`

  Expected: owner is absent and dispatcher still requires a generic closure.

- [ ] **Step 3: Implement owner command boundary**

  Use:

  ```rust
  enum KernelRuntimeCommandV2 {
      Agent {
          peer: AuthenticatedAgentPeerV2,
          lease: V2GenerationLease,
          request_id: RequestIdV2,
          operation: KernelAgentOperationV2,
      },
      Ingress {
          peer: AuthenticatedIngressPeerV2,
          lease: V2GenerationLease,
          request_id: RequestIdV2,
          operation: KernelIngressOperationV2,
      },
  }
  ```

  The owner holds all mutable services. Delete `FnMut(KernelServiceCommandV2)`
  from `KernelServiceDispatcherV2`.

- [ ] **Step 4: Connect AgentKernel handlers**

  Exhaustively call existing agent task/session, policy-core G3-G7, vault,
  approval verification, dispatch, and recovery functions. Mint handles only
  inside the owner from CSPRNG tokens and store only domain-separated token
  hashes. Queries return public projections; mutation replies are persisted
  before return.

- [ ] **Step 5: Connect IngressKernel handlers**

  Route UI authentication, begin/append/finalize/settle/abort/status and
  parser staging into kernel-owned input/vault state. Recompute chunk and
  cumulative digests from decrypted bytes. Only operations 48-50 may create
  ExtractedPage state.

- [ ] **Step 6: Map closed errors**

  Return `Result<KernelAgentSuccessV2, PublicStableCodeV2>` or
  `Result<KernelIngressSuccessV2, PublicStableCodeV2>`. The constructor checks
  the operation's frozen error set; rollback, corrupt durable state, audit
  failure, or unresolved effect terminates the owner instead.

- [ ] **Step 7: Run G1-G7 encrypted composition tests**

  Add one encrypted connection path through each gate and run all kerneld,
  policy-core, input-runtime, vault, agentd, ingressd, and approvald tests.

- [ ] **Step 8: Commit Task 8**

  Commit with `feat(kerneld): route typed v2 operations to kernel state`.

---

### Task 9: Execd typed service and kerneld client

**Files:**
- Create: `crates/savana-execd/src/v2_service.rs`
- Modify: `crates/savana-execd/src/state_owner.rs`
- Modify: `crates/savana-execd/src/lib.rs`
- Create: `crates/savana-kerneld/src/v2_executor_client.rs`
- Modify: `crates/savana-kerneld/src/v2_kernel_owner.rs`

**Interfaces:**
- Consumes: typed executor operations, Suite-1 client/server sessions, execd durable owner, and KernelExecutor edge lock.
- Produces: exhaustive tags 0/60/61/62/63 and the only kerneld-to-execd client.

- [ ] **Step 1: Write failing real encrypted executor test**

  Establish an authenticated KernelExecutor connection, dispatch one signed
  envelope, query the nonce, fetch the exact completion, acknowledge it, and
  query `Acknowledged`. Replaying a different core under the same nonce must
  poison/fail without a second effect.

- [ ] **Step 2: Run and verify RED**

  Run the focused execd test. Expected: typed service/client do not exist.

- [ ] **Step 3: Implement exhaustive execd dispatch**

  Match every `ExecutorOperationV2` variant directly to
  `ExecdStateOwnerV2`. Preserve zeroizing completion payloads and validate
  descriptor/payload/receipt digests before encoding success.

- [ ] **Step 4: Implement the fixed kerneld client**

  The client obtains the KernelExecutor generation/edge lease, performs one
  Suite-1 connection, verifies server identity and response request/tag
  binding, then closes. It exposes only four typed methods corresponding to
  tags 60-63.

- [ ] **Step 5: Run crash/replay tests and commit**

  Run execd, kerneld recovery, and G7 suites. Commit with
  `feat(execd): serve typed v2 executor operations`.

---

### Task 10: Final security matrix and documentation

**Files:**
- Create: `crates/savana-kerneld/tests/v2_final_mode.rs`
- Create: `crates/savana-kerneld/tests/v2_native_identity.rs`
- Create: `crates/savana-kerneld/tests/v2_operation_matrix.rs`
- Create: `crates/savana-execd/tests/v2_operation_matrix.rs`
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-07-28-savana-v2-final-activation-design.md`

**Interfaces:**
- Consumes: Tasks 1-9.
- Produces: final-mode evidence for deliverables 1-3 and an exact remaining-gap statement.

- [ ] **Step 1: Run the 42-operation matrix**

  For every tag, run success, malformed field, noncanonical encoding,
  wrong-role, expired deadline, replay, and public-error-set cases. Assert one
  and only one handler invocation for valid requests and zero for rejected
  requests.

- [ ] **Step 2: Run platform-native matrices**

  On the current native platform run all live peer/code identity tests. Record
  the other platform as unverified unless its native CI result is available;
  do not infer two-platform completion from cross compilation.

- [ ] **Step 3: Run full verification**

  Run:

  ```bash
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  cargo doc --workspace --all-features --no-deps
  cargo test --workspace --all-targets --all-features --locked
  ```

  Read every exit status and test summary. Any failure keeps its deliverable
  incomplete.

- [ ] **Step 4: Update claims**

  Mark the design status `implemented` only for verified deliverables.
  README must say V2 is the only production listener only if final-mode tests
  pass. Keep native keystore/rollback, remaining daemon entry points,
  deploy/watchdog/approvalctl, sandbox evidence, and untested native platform
  explicitly open.

- [ ] **Step 5: Commit Task 10**

  Commit with `test(kernel): verify v2 final activation`.
