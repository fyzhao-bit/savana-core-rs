# Savana V2 Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver the stable Rust V2 foundation: isolated protocol types and
canonical JARVIS-control messages, then an exactly-nine-crate workspace whose
new service crates compile without widening the public boundary.

**Architecture:** Keep the frozen V1 modules unchanged and add V2 under a
separate `v2` module with its own types and decoders. The first vertical slice
implements only the authenticated JARVIS-to-agentd control surface; it exposes
one opaque `TaskHandleV2`, closed statuses, and fixed-origin bootstrap URLs.
The six missing crates begin as narrow Rust libraries/binaries depending only
on the protocol or policy components their role requires.

**Tech Stack:** Rust 1.82.0, Cargo workspace resolver 2, `minicbor 0.25.1`,
`thiserror 1.0.69`, SHA-256/HMAC only where the frozen protocol requires it.

## Global Constraints

- The workspace production closure is exactly nine crates:
  `savana-kernel-protocol`, `savana-policy-core`, `savana-vault`,
  `savana-input-runtime`, `savana-agentd`, `savana-kerneld`,
  `savana-ingressd`, `savana-approvald`, and `savana-execd`.
- Every crate and target uses `#![forbid(unsafe_code)]`, Rust edition 2021,
  and Rust 1.82.
- V1 types and decoders remain byte-for-byte isolated from V2; neither decoder
  retries with the other version after failure.
- V2 metadata is definite-length canonical CBOR arrays only. Maps, floats,
  semantic tags, indefinite values, non-shortest encodings, unknown tags,
  omitted/trailing fields, and unconsumed bytes fail closed.
- V2 structs use exact array field order; enums use
  `[explicit_u16_tag, fields...]`; `Option<T>` uses `null` only for `None`.
- All capability byte constructors/accessors are crate-private. `Debug`
  renders only `TypeName(<opaque>)`.
- JARVIS receives only `TaskHandleV2`, `PublicTaskStatusV2`, and
  `JarvisBootstrapUrlV2`. It never receives user-derived content or another
  capability.
- The initial slice does not implement or encode the still-changing
  `BootstrapEpochBridge` deployment state.

---

### Task 1: V2 primitive and opaque-handle isolation

**Files:**

- Create: `crates/savana-kernel-protocol/src/v2/mod.rs`
- Create: `crates/savana-kernel-protocol/src/v2/primitives.rs`
- Create: `crates/savana-kernel-protocol/src/v2/handles.rs`
- Create: `crates/savana-kernel-protocol/tests/v2_foundation.rs`
- Modify: `crates/savana-kernel-protocol/src/lib.rs`

**Interfaces:**

- Consumes: existing `ProtocolError`, `StableCode`, and `minicbor`.
- Produces:
  `EndpointRoleV2`, `RequestIdV2`, `Digest32V2`, `Nonce32V2`, `BootIdV2`,
  `Ed25519KeyIdV2`, `HpkeX25519KeyIdV2`, `ReplayAeadKeyIdV2`,
  `Ed25519SignatureV2`, `UnixMillisV2`, `MonotonicNanosV2`,
  `TaskHandleV2`, and `JarvisBootstrapSelectorV2`.

- [x] **Step 1: Write failing foundation tests**

```rust
use std::any::TypeId;

use savana_kernel_protocol::v2::{
    decode_agent_control_operation_v2, AgentControlOperationV2, EndpointRoleV2,
    JarvisBootstrapSelectorV2, RequestIdV2, TaskHandleV2,
};

#[test]
fn endpoint_roles_use_the_frozen_v2_tags() {
    let cases = [
        (EndpointRoleV2::JarvisAgentControl, 1_u16),
        (EndpointRoleV2::AgentKernel, 2),
        (EndpointRoleV2::IngressKernel, 3),
        (EndpointRoleV2::KernelExecutor, 4),
        (EndpointRoleV2::AgentApproval, 5),
        (EndpointRoleV2::IngressApproval, 6),
        (EndpointRoleV2::ApprovalAdmin, 7),
    ];
    for (role, want) in cases {
        assert_eq!(minicbor::to_vec(role).unwrap(), [0x81, want as u8]);
    }
}

#[test]
fn task_handle_is_fixed_width_and_debug_redacted() {
    let mut operation = vec![0x82, 0x0b, 0x81, 0x58, 0x20];
    operation.extend_from_slice(&[0x5a; 32]);
    let handle = match decode_agent_control_operation_v2(&operation).unwrap() {
        AgentControlOperationV2::GetTaskStatus(request) => request.task(),
        _ => unreachable!(),
    };
    assert_eq!(format!("{handle:?}"), "TaskHandleV2(<opaque>)");
    assert!(decode_agent_control_operation_v2(
        &[0x82, 0x0b, 0x81, 0x41, 0x5a],
    )
    .is_err());
}

#[test]
fn selector_and_task_handle_remain_distinct_types() {
    assert_ne!(
        TypeId::of::<JarvisBootstrapSelectorV2>(),
        TypeId::of::<TaskHandleV2>(),
    );
    let request = RequestIdV2::new([1; 16]);
    assert_eq!(request.as_bytes(), &[1; 16]);
}
```

- [x] **Step 2: Run the test and verify RED**

Run:

```bash
cargo test -p savana-kernel-protocol --test v2_foundation --locked
```

Expected: compilation fails because `savana_kernel_protocol::v2` does not
exist.

- [x] **Step 3: Implement exact V2 primitive types**

Implement explicit role matching and fixed-byte newtypes. Public non-secret
primitives expose `new`/`as_bytes`; opaque types expose neither.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRoleV2 {
    JarvisAgentControl,
    AgentKernel,
    IngressKernel,
    KernelExecutor,
    AgentApproval,
    IngressApproval,
    ApprovalAdmin,
}

impl EndpointRoleV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::JarvisAgentControl => 1,
            Self::AgentKernel => 2,
            Self::IngressKernel => 3,
            Self::KernelExecutor => 4,
            Self::AgentApproval => 5,
            Self::IngressApproval => 6,
            Self::ApprovalAdmin => 7,
        }
    }
}
```

Use separate macros for public fixed bytes and opaque fixed bytes so a future
refactor cannot accidentally add an accessor to capability types.

- [x] **Step 4: Run foundation tests and verify GREEN**

Run:

```bash
cargo test -p savana-kernel-protocol --test v2_foundation --locked
```

Expected: 3 passed, 0 failed.

- [x] **Step 5: Run V1 regression tests**

Run:

```bash
cargo test -p savana-kernel-protocol --all-targets --locked
```

Expected: all existing V1 tests and the new V2 tests pass.

### Task 2: Closed JARVIS control DTOs and canonical codec

**Files:**

- Create: `crates/savana-kernel-protocol/src/v2/jarvis.rs`
- Create: `crates/savana-kernel-protocol/src/v2/cbor.rs`
- Create: `crates/savana-kernel-protocol/tests/v2_jarvis_control.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/mod.rs`

**Interfaces:**

- Consumes: Task 1 V2 primitives and opaque handles.
- Produces:
  `FixedOriginV2`, `BootstrapKindV2`, `PublicServiceStateV2`,
  `PublicFailureClassV2`, `JarvisBootstrapUrlV2`,
  `JarvisBootstrapActionV2`, `PublicTaskStatusV2`,
  `AgentControlOperationV2`, `encode_agent_control_operation_v2`, and
  `decode_agent_control_operation_v2`.

- [x] **Step 1: Write failing closed-surface tests**

The test constructs raw literal canonical CBOR so expected bytes do not reuse
the production encoder:

```rust
#[test]
fn get_task_status_is_exact_tag_11_with_one_opaque_handle() {
    let mut wire = vec![0x82, 0x0b, 0x81, 0x58, 0x20];
    wire.extend_from_slice(&[0x44; 32]);
    let decoded = decode_agent_control_operation_v2(&wire).unwrap();
    assert_eq!(decoded.tag(), 11);
    assert_eq!(encode_agent_control_operation_v2(&decoded).unwrap(), wire);
}

#[test]
fn unknown_or_cross_endpoint_operation_tags_fail_closed() {
    assert!(decode_agent_control_operation_v2(&[0x82, 0x14, 0x80]).is_err());
    assert!(decode_agent_control_operation_v2(&[0x82, 0x18, 0x29, 0x80]).is_err());
}

#[test]
fn public_status_rejects_success_payload_or_wrong_failure_class() {
    assert!(decode_public_task_status_v2(&[0x82, 0x08, 0x41, 0x78]).is_err());
    assert!(decode_public_task_status_v2(&[0x82, 0x0a, 0x81, 0x07]).is_err());
}
```

- [x] **Step 2: Run and verify RED**

Run:

```bash
cargo test -p savana-kernel-protocol --test v2_jarvis_control --locked
```

Expected: compilation fails because the JARVIS V2 DTOs and codec do not exist.

- [x] **Step 3: Implement closed enums and operation bodies**

Use the frozen tags:

```text
FixedOriginV2: Jarvis8765=1, Approval8766=2, Ingress8767=3, Agent8768=4
BootstrapKindV2: Ingress=1, Approval=2, Agent=3
PublicServiceStateV2: Starting=1, Ready=2, DegradedFailClosed=3, Fenced=4
PublicFailureClassV2: Policy=1, Input=2, Approval=3, Connector=4,
                      Infrastructure=5, ResultGate=6, Audit=7,
                      ReleaseEvidence=8
AgentControlOperationV2: Health=0, PrepareIngress=10,
                         GetTaskStatus=11, CancelTask=12
```

Encode every enum as `[tag_u16, fields...]`, including unit variants. Reject
`Some(JarvisBootstrapActionV2::None)`, a bootstrap action whose open variant
does not match its URL kind, `Audit` outside
`EffectSucceededOutputQuarantined`, and every unknown tag/shape.

- [x] **Step 4: Implement canonical decode**

The decoder must:

1. scan exactly one value and reject maps/floats/tags/indefinite values;
2. decode only `AgentControlOperationV2`;
3. consume all bytes;
4. re-encode and compare byte-for-byte;
5. return `ProtocolNonCanonicalCbor` for a semantically decodable but
   non-canonical integer/length and `ProtocolMalformedCbor` for bad shape.

- [x] **Step 5: Run JARVIS tests and all protocol regressions**

Run:

```bash
cargo test -p savana-kernel-protocol --test v2_jarvis_control --locked
cargo test -p savana-kernel-protocol --all-targets --locked
```

Expected: all pass with no ignored test.

### Task 3: Exactly-nine-crate workspace boundary

**Files:**

- Modify: `Cargo.toml`
- Create: `crates/savana-vault/Cargo.toml`
- Create: `crates/savana-vault/src/lib.rs`
- Create: `crates/savana-input-runtime/Cargo.toml`
- Create: `crates/savana-input-runtime/src/lib.rs`
- Create: `crates/savana-agentd/Cargo.toml`
- Create: `crates/savana-agentd/src/lib.rs`
- Create: `crates/savana-ingressd/Cargo.toml`
- Create: `crates/savana-ingressd/src/lib.rs`
- Create: `crates/savana-approvald/Cargo.toml`
- Create: `crates/savana-approvald/src/lib.rs`
- Create: `crates/savana-execd/Cargo.toml`
- Create: `crates/savana-execd/src/lib.rs`
- Create: `crates/savana-kernel-protocol/tests/workspace_boundary.rs`

**Interfaces:**

- Consumes: Task 1 `EndpointRoleV2`.
- Produces: a Cargo production workspace containing exactly the nine frozen
  crate names. The legacy `libsavana-ner` and `savana-core-py` directories
  remain untouched but are not workspace production members.

- [x] **Step 1: Write a failing workspace-boundary test**

The test runs `cargo metadata --no-deps --format-version 1`, parses the
workspace member package names, sorts them, and compares them with this
hand-written literal:

```rust
[
    "savana-agentd",
    "savana-approvald",
    "savana-execd",
    "savana-ingressd",
    "savana-input-runtime",
    "savana-kernel-protocol",
    "savana-kerneld",
    "savana-policy-core",
    "savana-vault",
]
```

- [x] **Step 2: Run and verify RED**

Run:

```bash
cargo test -p savana-kernel-protocol --test workspace_boundary --locked
```

Expected: the literal differs from the current five-member workspace.

- [x] **Step 3: Add the six crate manifests and narrow library roots**

Each new root initially contains only:

```rust
#![forbid(unsafe_code)]
```

Do not add public constructors, network listeners, persistence formats,
credentials, or placeholder business APIs. Those require their own failing
behavioral tests in later tasks.

- [x] **Step 4: Replace workspace membership**

List the exact nine production crates explicitly. Do not delete or rewrite
the two legacy directories; remove only their workspace membership.

- [x] **Step 5: Run metadata, check, and boundary test**

Run:

```bash
cargo metadata --no-deps --format-version 1
cargo check --workspace --all-targets --locked
cargo test -p savana-kernel-protocol --test workspace_boundary --locked
```

Expected: metadata lists exactly nine workspace members and all crates check.

### Task 4: Foundation verification and handoff

**Files:**

- Modify: `README.md`
- Modify: this implementation plan's completed checkboxes

**Interfaces:**

- Consumes: Tasks 1–3.
- Produces: a verified first implementation checkpoint and commands for the
  next slice.

- [x] **Step 1: Format and lint**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Expected: zero formatting differences and zero warnings.

- [x] **Step 2: Run stable test gates**

Run:

```bash
cargo test -p savana-kernel-protocol -p savana-policy-core --all-targets --locked
cargo test -p savana-kerneld \
  --lib \
  --locked \
  -- --skip server::tests::partial_worker_spawn_failure_joins_started_workers_before_socket_cleanup
```

Expected: protocol/policy pass. The kerneld command is diagnostic only until
the pre-existing `IdentitySocketPermissions` host-fixture failure and its
poison cascade are separately fixed; do not claim the full kerneld baseline
is green.

- [x] **Step 3: Update README boundary**

Document protocol V2 as a separately typed pre-dispatch foundation and list
the exact nine workspace crates. State explicitly that bridge deployment and
V2 mutations beyond JARVIS control remain closed.

- [x] **Step 4: Review changed files**

Run:

```bash
git diff --check
git status --short
git diff -- Cargo.toml crates/savana-kernel-protocol crates/savana-vault \
  crates/savana-input-runtime crates/savana-agentd crates/savana-ingressd \
  crates/savana-approvald crates/savana-execd README.md
```

Expected: no whitespace errors, no generated `target` files, and no changes
to the existing uncommitted design documents beyond their prior state.

Checkpoint result:

- The protocol/policy stable gate, workspace check, format, clippy, and
  boundary tests pass.
- The kerneld diagnostic still fails first in the pre-existing socket fixture
  with `IdentitySocketPermissions`, followed by process-global mutex poison
  cascades.
- V2 public decoding now requires the private canonical context and is exposed
  only through byte-exact wrapper functions; the scanner applies one
  cumulative item budget.
- Authority-side minting remains deliberately unopened. Before agentd can
  dispatch tag 10, the design must resolve how the sibling crate invokes
  CSPRNG `TaskHandleV2` generation and keyed
  `JarvisBootstrapSelectorV2` derivation without exposing raw token
  constructors or accessors as general protocol API.
