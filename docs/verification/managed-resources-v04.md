# v0.4 first-party managed-resource source

Implementation record, 2026-09-19. This is a Rust library integration with the
existing encrypted G4 owner and G7 preparation, not a deployed MCP connector or
Linux service acceptance result.

## Identity contract

The first concrete source is a bounded collection of private byte objects owned
by Savana itself. It is deliberately not a filesystem-path/inode adapter. The
owner generates a random 256-bit object birth ID, checks it against all live and
deleted IDs, and never accepts an object ID from a writer. The stable key is
`(source, namespace, object, incarnation=0)`. New births use fresh IDs instead of
recycling IDs with a new incarnation. Renaming or changing content increments an
object revision, not its stable key. Duplicate display labels are allowed and
never used to resolve execution identity.

The canonical private selector is
`savana-object-v1:<source-hex>:<namespace-hex>:<object-hex>`. Its target-bound digest
matches the existing closed BusinessRequest codec for both fixed POST and MCP
tools/call profiles. This is a selector, **not a capability**. Existing root/task,
descriptor, registry, approval, G1–G7 and effect-time gates remain required.

Deletion clears current label/content and retains a versioned identity tombstone.
There is no resurrection, compaction, reuse, refund or reset API. New creation is
a new object, even if its label/content equals a deleted object's. Re-ingesting
the same external business entity as a fresh object is **not** safe external
deduplication: an external connector must supply its own reviewed birth/alias
mapping. The Agent cannot call these source administration methods.

## Signed registration and private host interfaces

`ManagedSourcePolicyV04` pins installation, source, namespace, target identity,
resource-fact issuer, time window and lifetime object/byte/mutation limits. The
host selects the administrator public key independently and calls
`VerifiedManagedSourceV04::verify`; proposals cannot select trust. Verification
requires bounded canonical closed JSON and a purpose-separated Ed25519 signature.
The owner rechecks its own installation namespace and registration time.

Public Rust library methods on `DurableG4StateV2` (not wire/SDK endpoints):

| Method | Private host responsibility / result |
| --- | --- |
| `install_managed_source_v04` | Authenticated administrator; immutable signed source registration |
| `create_managed_resource_v04` | Authenticated source writer; fresh owner-generated stable key after commit |
| `update_managed_resource_v04` | Authenticated source writer; exact expected revision, edit or tombstone |
| `managed_resource_v04` | Authenticated private reader; current bytes/label/revision or tombstone |
| `issue_managed_resource_evidence_v04` | Trusted source issuer; signs an action-bound fact read from this owner |

A subsequent batch adds a sixth private host method,
`managed_execution_snapshot_v04`, for immutable per-execution inputs; see
[execution input snapshots](execution-input-snapshots-v04.md). It is an audit/bridge
read, not an execution permission or outbound data capability.

Later host integration adds `bind_managed_dispatch_input_v04` for automatic
first-party fact binding before G7 and `check_managed_execution_handoff_v04` for
the exact pre-seal check. These are private Rust host methods, not additional
model tools or SDK endpoints. See [managed admission](managed-admission-v04.md)
for the optional Linux issuer configuration and remaining enrollment/UI work.
A later private `apply_managed_admin_v04` transaction adds signed administration
and durable retry receipts, including atomic storage/accounting enrollment; see
[managed administration](managed-admin-v04.md). This is not yet a wire endpoint.

Registration must precede every dispatch policy in the same source/namespace.
Installing over an existing external dispatch policy is rejected even before its
first use. Exact source reinstall is idempotent; any changed policy is rejected.
An installed dispatch policy for a managed source must pin the same issuer and
installation. A source may exist before a task; creating it does not authorize
that task to use newly appearing resources.

Issuer key provisioning remains the deployment host's responsibility. The issuer
method accepts a separately provisioned SigningKey and checks its public key
against stored policy. No production key generation, embedded seed, cloud
credential or secret-export endpoint was added. This software-key seam still
needs the target platform's approved signing adapter before production use.

## Evidence, admission and replay

Managed resource facts add a signed optional `managed_revision` field. Absence
retains the exact old fact encoding/digest for external issuers. Managed sources
require a nonzero revision. External sources reject this field rather than
silently treating an unverified revision as owner evidence.

At new G7 preparation, under the same owner transaction as original task/quota/
journal and stable debit, the owner rechecks the actual catalog: source, namespace,
pinned issuer, canonical target-bound selector, live object, and exact current
revision. The existing fact verifier also checks whole-action binding, signature
and admission-time validity. Thus an edit/delete between fact issuance and G7
admission rejects the stale request without any debit. A refreshed fact for the
same stable object does not reset its per-resource consumption.

Replay and reopen verify the original fact at its original admission time, its
original reservation and execution ID, and its retained catalog identity/version
history. They do not require the object to remain live or reissue a fact. Current
task/policy/lease checks still apply to replay. Historical revision validation
uses retained monotonic revision/tombstone state and authenticated original
admission records, **not a full versioned content archive**.

These are new-reservation admission guarantees. An actual provider must still
bind its effect to the admitted object/version under the existing effect gate;
this batch does not implement that provider transaction. Source-admin edits are
trusted ingestion/administration, not Agent-authorized business effects.

The snapshot batch now retains actual admitted bytes in the same G7 commit;
these pins survive edits/deletion and never backfill legacy inputs. Connecting
them to the authenticated executor/provider route is still pending. Source
deletion therefore does not erase private copies retained for admitted executions.

## Durability and bounds

The catalog is inside the same encrypted, locked, anchored snapshot as the G7
journal and stable ledger. Precommit failure leaves the old state intact.
Uncertain commit returns no new object key or usable owner state; normal recovery
reconciles the anchored snapshot. Lost responses may leave a committed object;
there is no exactly-once external ingestion protocol in these private methods.

Signed limits are capped at 8 sources, 1,024 lifetime objects per source, 32 KiB
per object's current content, 256 UTF-8 bytes per label, and 65,536 source
mutations. Tombstones consume object capacity, and mutations never refund.
The existing aggregate 8 MiB continuation snapshot cap also applies; not all
individual maxima can be simultaneously allocated. Historical snapshot files
and freed memory are not guaranteed securely erased by content deletion.

Only explicit source registration opts into payload schema 7. Empty catalogs
are omitted, preserving schema 4/5/6 encoding; those formats remain readable.
There is no downgrade or automatic migration of live installation state. Older
binaries reject schema 7. Source fingerprints are not production release signing.

## Verification and remaining work

`durable_managed_resource_tests.rs` contains 15 tests for immutable identity,
duplicate labels, version freshness, tombstones, lifetime bounds, issuer/selector
substitution, registration ordering, canonical signatures, encrypted restart,
schema mismatch/corrupt revision totals, precommit and uncertain-anchor failure,
original-ID replay and stable debit after edit/delete, and exact business-codec
selector compatibility. They use real owner files and test rollback anchors;
they are not hardware-backed Linux acceptance tests or live provider calls.

```sh
cargo test -p savana-policy-core --lib managed_ --locked
cargo test -p savana-policy-core --lib --locked
cargo test -p savana-continuation-core --all-targets --locked
cargo check -p savana-kerneld --locked
tools/check-frozen-v2-core.sh
```

Still pending: host authentication/RPC plumbing, target-platform signer and
hardware anchor acceptance, external provider identity adapters, concrete provider
effect/read-set integration, dynamic root compiler, residual contracts and K1–K6
replacement, exclusive publisher/InferenceSpec, SDK/UI, durable review queue/fake
worker. Current root matching still limits admitted resources. Private source
errors, data and IDs must not be exposed to a model as privacy oracles. There is
no new end-to-end noninterference or ProductComplete claim. Google Cloud and
DeepSeek remain disabled placeholders.

Local macOS validation: **273/273 policy-core library tests** and **34/34 finite
continuation-core tests** passed, including the 15 new managed-resource cases.
Kernel compilation, targeted formatting, diff whitespace and frozen-source
fingerprint checks also passed. Library-only Clippy completed with the same three
pre-existing policy warnings (argument count, large enum, manual range pattern);
this is not a clean strict-workspace lint claim. These results do not include
native Linux or live provider acceptance.
