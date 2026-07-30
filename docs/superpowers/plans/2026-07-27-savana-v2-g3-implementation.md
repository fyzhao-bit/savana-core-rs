# Savana V2 G3 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the complete V2 G3 label lattice, source initialization,
normal derivation, provenance records, root-evidence accounting, and
domain-separated semantic digests in Rust.

**Architecture:** `savana-policy-core::v2` owns all G3 semantic transitions.
Public value types have private fields and validated constructors; callers
cannot supply an already-computed derived label or provenance digest.
`savana-kernel-protocol::v2` supplies only distinct fixed-width digest/identity
newtypes and canonical encoders. G3 performs no I/O and has no daemon,
transport, vault, approval, or executor dependency.

**Tech Stack:** Rust 1.82, `minicbor` 0.25.1, SHA-256 via `sha2` 0.10.9.

## Global Constraints

- V1 and V2 Rust types remain isolated; no fallback decode or conversion.
- `#![forbid(unsafe_code)]` remains effective in every crate.
- Integrity order is
  `KernelTrusted < UserAuthorized < ExternalUntrusted`.
- Confidentiality is the frozen diamond lattice; `PlannerAbstract ∨
  AgentMasked = VaultBound`.
- Normal derivation intersects readers and effects; effects are additionally
  intersected with the verified signed-policy allowance.
- Zero-parent derivation is forbidden.
- Root evidence is sorted, unique, and bounded to 64 exact digests.
- No opaque handle, request ID, transport sequence, or browser token enters a
  semantic digest.
- Every digest uses the exact domain and canonical array shape in protocol
  section 7.3.
- This dirty worktree is not staged or committed without an explicit user
  request.

---

### Task 1: G3 label algebra

**Files:**

- Create: `crates/savana-policy-core/src/v2/mod.rs`
- Create: `crates/savana-policy-core/src/v2/labels.rs`
- Create: `crates/savana-policy-core/tests/v2_g3_labels.rs`
- Modify: `crates/savana-policy-core/src/lib.rs`

**Interfaces:**

- Consumes: no V2 semantic types.
- Produces:
  `IntegrityV2`, `ConfidentialityV2`, `ReaderSetV2`, `EffectSetV2`,
  `SecurityLabelV2`, `G3Error`, and
  `SecurityLabelV2::derive_normal(&[SecurityLabelV2], EffectSetV2)`.

- [x] **Step 1: Write the failing lattice tests**

```rust
#[test]
fn confidentiality_is_the_frozen_diamond() {
    assert_eq!(
        ConfidentialityV2::PlannerAbstract.join(
            ConfidentialityV2::AgentMasked,
        ),
        ConfidentialityV2::VaultBound,
    );
}

#[test]
fn normal_derivation_never_improves_authority() {
    let left = SecurityLabelV2::from_verified_source(
        IntegrityV2::KernelTrusted,
        ConfidentialityV2::PlannerAbstract,
        ReaderSetV2::KERNEL.union(ReaderSetV2::EXTERNAL_PLANNER),
        EffectSetV2::READ.union(EffectSetV2::EXECUTE),
    );
    let right = SecurityLabelV2::from_verified_source(
        IntegrityV2::ExternalUntrusted,
        ConfidentialityV2::AgentMasked,
        ReaderSetV2::KERNEL.union(ReaderSetV2::AGENT),
        EffectSetV2::READ.union(EffectSetV2::SEND),
    );
    let derived = SecurityLabelV2::derive_normal(
        &[left, right],
        EffectSetV2::READ.union(EffectSetV2::EXECUTE),
    )
    .unwrap();
    assert_eq!(derived.integrity(), IntegrityV2::ExternalUntrusted);
    assert_eq!(derived.confidentiality(), ConfidentialityV2::VaultBound);
    assert_eq!(derived.readers(), ReaderSetV2::KERNEL);
    assert_eq!(derived.effects(), EffectSetV2::READ);
}
```

- [x] **Step 2: Run and verify RED**

Run:

```bash
cargo test -p savana-policy-core --test v2_g3_labels --locked
```

Expected: compilation fails because `savana_policy_core::v2` is absent.

- [x] **Step 3: Implement the closed lattice**

Implement explicit tags, the two join operations, closed `u16` bit sets, and
the nonempty normal-derivation fold. `ReaderSetV2::from_bits` and
`EffectSetV2::from_bits` return `None` for any unknown bit.

- [x] **Step 4: Run and verify GREEN**

Run:

```bash
cargo test -p savana-policy-core --test v2_g3_labels --locked
```

Expected: all G3 label tests pass.

### Task 2: Distinct semantic IDs and canonical provenance DTOs

**Files:**

- Modify: `crates/savana-kernel-protocol/src/v2/primitives.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/mod.rs`
- Create: `crates/savana-policy-core/src/v2/provenance.rs`
- Create: `crates/savana-policy-core/tests/v2_g3_provenance.rs`

**Interfaces:**

- Consumes: Task 1 label types plus `Digest32V2`, `UnixMillisV2`.
- Produces:
  `ValueInternalIdV2`, `DurableRunIdV2`, `ActionIntentIdV2`,
  `SourceKindV2`, `ProvenanceRecordV2`, and `RootEvidenceV2`.

- [x] **Step 1: Write failing source and root tests**

Test that:

```rust
assert!(RootEvidenceV2::new(vec![digest(2), digest(1)]).is_ok());
assert!(RootEvidenceV2::new(vec![digest(1), digest(1)]).is_err());
assert!(RootEvidenceV2::new((0..65).map(digest).collect()).is_err());
```

Also test every source's forced integrity/confidentiality/readers and reject
zero-parent `Derived`, cross-run parents, missing required roots, and
caller-selected labels.

- [x] **Step 2: Run and verify RED**

Run:

```bash
cargo test -p savana-policy-core --test v2_g3_provenance --locked
```

Expected: compilation fails because the G3 provenance API is absent.

- [x] **Step 3: Implement source constructors**

Provide one constructor per closed `SourceKindV2`. Constructors compute the
initial label internally and accept exact parent/root records. The generic
record struct has private fields and no unchecked public constructor.

- [x] **Step 4: Implement root union**

Merge sorted roots from all parents, insert source-mandatory roots, reject
duplicates inside one claimed source set, and fail before producing a record
when the union exceeds 64.

- [x] **Step 5: Run and verify GREEN**

Run:

```bash
cargo test -p savana-policy-core --test v2_g3_provenance --locked
```

Expected: all provenance-transition tests pass.

### Task 3: G3 semantic digest domains

**Files:**

- Create: `crates/savana-policy-core/src/v2/digest.rs`
- Create: `crates/savana-policy-core/tests/v2_g3_digests.rs`
- Modify: `crates/savana-policy-core/src/v2/mod.rs`

**Interfaces:**

- Consumes: Task 2 canonical DTOs.
- Produces:
  `value_digest_v2`, `provenance_digest_v2`, `argument_digest_v2`,
  `provenance_set_digest_v2`, `evidence_digest_v2`, and
  `token_set_digest_v2`.

- [x] **Step 1: Write independent reference-vector tests**

Each test builds literal canonical bytes without calling the production
encoder, hashes `domain || bytes` with `sha2` in test code, and compares with
the production function.

- [x] **Step 2: Run and verify RED**

Run:

```bash
cargo test -p savana-policy-core --test v2_g3_digests --locked
```

Expected: compilation fails because the digest functions are absent.

- [x] **Step 3: Implement exact domain-separated hashes**

Use:

```rust
fn domain_hash(domain: &[u8], canonical: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Digest32V2::new(hasher.finalize().into())
}
```

Validate sorted/unique/count invariants before encoding. Never hash a handle,
request ID, transport sequence, or caller-provided aggregate digest.

- [x] **Step 4: Run and verify GREEN**

Run:

```bash
cargo test -p savana-policy-core --test v2_g3_digests --locked
```

Expected: all independent vectors pass.

### Task 4: G3 security and regression gate

**Files:**

- Modify: `README.md`
- Modify: this plan's completed checkboxes.

**Interfaces:**

- Consumes: Tasks 1–3.
- Produces: a documented, reviewed G3 checkpoint used by G4 and G5.

- [x] **Step 1: Add negative API tests**

Add compile-fail doctests proving provenance records cannot be constructed
from public fields and a caller cannot replace their computed label or digest.

- [x] **Step 2: Run complete verification**

Run:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test -p savana-kernel-protocol -p savana-policy-core \
  --all-targets --locked
git diff --check
```

Expected: every command exits zero.

- [x] **Step 3: Independent review**

Review exact section-7 coverage, lattice tables, source rules, root bounds,
canonical bytes, domain strings, public API surface, and regression output.
Fix every Critical or Important issue before starting G4.
