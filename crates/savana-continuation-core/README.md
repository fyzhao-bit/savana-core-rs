# Savana continuation core

First additive implementation batch for the v0.4 **Linux security-kernel** target.
This library is part of the planned userspace Savana TCB, not a Linux OS kernel
module and not a replacement for the V2 authorization/approval/transport gates.

## Implemented in this batch

- Validated finite total public semantics with bounded states, commands, edges
  and output bytes. Root, semantics, renderer and observer context are bound.
- Strict inference fixed-point exploration: all protected initial ordered pairs,
  every common public command and independently interleaved private successors.
  Complete logical message bytes are compared. Errors/catalogs/absences must be
  represented in those bytes or the total input semantics, not hidden outside it.
- Concrete local counterexamples and an independent inductive-certificate
  checker which regenerates successors. Counterexample traces are NOT cloud data.
- Publicly ranked finite release search. This first candidate language is static
  total postprocessing of complete logical messages; it does not implement all
  policy choices in the PDF's unavailable Python package. Old counterexamples
  eliminate a policy only after concrete replay under that policy.
- Exact finite labeled partition refinement plus independent quotient checking.
  Safety/goal colors, public labels and private event labels are preserved. This
  is not a C1–C5 compiler, BC5 fairness certificate or K6 progress proof.
- Pure, all-or-none multi-domain ledger transitions, stable resource keys,
  original execution/request bindings, exact replay and stale-update rejection.
  All configured domains are mandatory for each reservation in this profile.
- Closed deterministic observation projectors with pin/freeze, original bytes,
  read-without-refresh, canonical snapshots and externally bound restore checks.
  Declared Boolean projection is NOT automatically Strict Inference compatible.

Resource exhaustion is `Unknown` for privacy checking/search; it is not Safe or
NoSolution. An empty/invalid model cannot prove safety vacuously. A result applies
only to the supplied trusted finite semantics, NOT arbitrary business data.

The `planning` module adds the fused V2/v0.4 **staging** protocol: closed constant
views, optional bounded advice, fixed-cut envelope reconstruction, once-only plan
selection, registered-order compilation and started-prefix-preserving replacement.
Its durable host integration does not yet enable production model egress or
effects. See [exact supported scope](../../docs/verification/fused-planning-v04.md).
Run the offline fixture with `cargo run -p savana-continuation-core --example
fused_planning --offline`; it is not a live model or business executor.

## Host boundary

The trusted host supplies the compiler/model and approved initial baseline. A
candidate must not supply a convenient subset of real transitions or redefine
private answers as public baseline. A complete real-command abstraction must
include unsupported requests and argument classes. Fixed model tables are not a
proof of that abstraction or of universal identity anonymity.

The ledger and observation methods themselves are in-memory transitions. Snapshot
digests check content, not freshness, encryption, ownership or anti-rollback.
The policy core now wraps them in the existing encrypted `DurableG4StateV2` owner,
using its transaction and independent rollback-anchor interface. Registration
requires a verified, bounded storage profile bound to an installed task authority.
Restoration reconstructs all consumption from original reservations rather than
trusting counters. See [storage integration](../../docs/verification/continuation-storage-v04.md).

The host wrapper also supports an explicitly signed opt-in for additional G7
accounting. It verifies exact-action resource facts with a pinned issuer and
computes all charges from signed rules, in the same transaction as original G7
preparation. No new root authority or disclosure permission is created. See
[dispatch integration](../../docs/verification/continuation-dispatch-v04.md).
The fixed publisher, current-reader gates and full v0.4 egress mediation are not
connected yet; this is not Strict Inference activation. Hardware anchor acceptance
remains a deployment requirement; the new fault tests use a test anchor.
No method here grants dispatch/disclosure authority. There is no production RPC,
cloud caller, credential, transport, root issuer or arbitrary-code interpreter.

Do not present these primitives as a deployed Strict Inference product. Remaining
work is tracked in [the implementation plan](../../docs/research/v04-product-implementation.md).

## Validation

```sh
cargo fmt -p savana-continuation-core -- --check
cargo clippy -p savana-continuation-core --all-targets --locked -- -D warnings
cargo test -p savana-continuation-core --all-targets --locked
cargo test -p savana-continuation-core --doc --locked
```

The test suite includes 864 generated finite systems compared against an
independent greatest-fixed-point elimination oracle, plus mutated certificates,
private answers/recovery/catalog changes, multi-domain failures, stale updates
and frozen-history reopening. Policy-core tests additionally exercise the actual
encrypted owner and uncertain anchor commits. These are newly executed tests, not
the historical S2–S5 results from the PDF.

Linux CI is in `.github/workflows/continuation-core-linux.yml`. Current local
development occurs on macOS; passing local tests does not establish native Linux
service, Landlock/seccomp or hardware-anchor behavior. Cloud deployment and the
requested DeepSeek-V4.1-Flash worker remain disabled placeholders.
