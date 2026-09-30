# Evidence-grounded private continuations (experimental Rust prototype)

This workspace crate implements the bounded research prototype requested on
2026-09-05. It is **not installed in the production V2 daemon/RPC path** and does
not mint anything the existing executor accepts as a dispatch grant. Frozen
production code, G1–G7, approvals, signing and deployment state are unchanged.

## What runs

A signed root rule authorizes requesting missing invoices for one account/month,
through one pinned source, an immutable merchant-directory version and one
reviewed request profile. The root contains no order IDs. Signed, query-bound
metadata discovers them at runtime; matching rows instantiate exact
order/version/merchant/contact tuples. Free-text notes and amounts cannot affect
authority, snapshot consistency or generated payloads.

Each order may be reserved once in this task, across all discovery rounds and
reopens. The request contains only that order's ID/version, its directory-bound
merchant/contact and a fixed invoice-request template. A worker cannot replace
any field, operation, target or credential at the checked boundary. The owner
commits an attempt fence before invoking the trusted transport, retains response
bytes before classifying them, and commits the outcome before publishing it.
Anything other than checked success is Unknown: there is no refund or retry.

Only `PlannerPort::exchange` crosses the untrusted planner boundary. It supports
**three commands**:

```json
{"command":"Observe"}
{"command":"Discover","epoch":1}
{"command":"RequestInvoice","epoch":3,"handle":"opaque handle from the view"}
```

Replies contain only a schema, view epoch, discovery flags and ordered opaque
slots with closed statuses, or a constant `Unavailable`. There are no arbitrary
predicates, user-selected fields, raw errors, payloads, URLs, policy edits,
completion assertions or mapper callbacks. IDs use a task-private random PRF key
and slot index, not hashes of low-entropy private data. Repeated observations
reuse the same cached view and do not consume additional disclosure revisions.

## Trusted host API (not model interfaces)

| API | Duty |
| --- | --- |
| `Workflow::create` / `reopen` | Verify deployment-selected issuer/context, initialize or recover the exclusive owner |
| `pending_discovery` | Obtain the private, root/query-bound request for authenticated fact services |
| `accept_discovery` | Verify distinct source/directory signatures, scope, freshness, version consistency and tuple binding; atomically derive slots |
| `pending_request` | Get the exact private V2 `BusinessRequestV2` for a reserved slot |
| `execute` | Compare the actual worker bytes and transport identities, commit the attempt fence, retain/classify the actual response |
| `revoke` | Authenticated host cancellation; never undo an already attempted external effect |
| `FileStore::open` | Exclusive 0600-file/0700-directory encrypted storage with an external rollback anchor |

Signing helpers are for trusted issuers/fact services. Giving the model these
keys, the owner object, the storage adapter or a transport implementation breaks
the threat model. A Rust facade is not process isolation.

## Run the offline fixture

```sh
cargo test -p savana-private-workflow --all-targets --locked
cargo clippy -p savana-private-workflow --all-targets --no-deps --locked -- -D warnings
private_fixture_dir=$(mktemp -d)
cargo run -p savana-private-workflow --example invoice_loop --locked -- "$private_fixture_dir"
```

The example canonicalizes the directory; it must be new, empty and mode 0700.
It discovers two objects over two rounds, emits two **offline fixture calls**,
reopens encrypted storage and verifies that rediscovery/reopen cannot send again.
Only the planner transcript is printed. It uses explicit deterministic demo
signing/encryption keys and a process-local test anchor, never production keys.
It leaves its encrypted fixture file in the supplied temporary directory. The
test anchor cannot recover across a new process; use a fresh directory each run.

`FileStore` requires the same `RollbackProtectedStateAnchorV2` interface as the
production G4 owner. No hardware implementation is configured by this crate.
It authenticates namespace/sequence/previous-head in AES-256-GCM, fsyncs file and
directory, then advances the external anchor. Exactly one authenticated adjacent
replacement may be recovered after anchor uncertainty. Storage errors poison
the owner; an attempted operation without a retained response reopens Unknown.

## Scope, privacy and evidence

Hard bounds: 32 distinct orders, eight discovery rounds, 128 distinct disclosed
views, one attempt per order, one root revision, one directory version and one
fixed POST business profile. The default fixture uses smaller limits. The
authenticated provider must enforce `order_version` and exact-request success
semantics. Directory/source signatures authenticate their scoped statements;
they do not establish the truth of arbitrary prose or an untrusted service.

The declared leakage is order-slot count/equality across rounds, eligibility,
freshness/protocol-consistency outcomes, coarse status, progress, discovery
availability and view epochs. Timing, system/network side channels, provider
behavior and hardware trust are excluded. Repeated refusals cannot query an
arbitrary secret predicate, but fixed refusal alone is not a timing guarantee.
The projection does not claim to hide the task's structural shape or arbitrary
semantic inferences from these permitted observations.

See [specification and research boundaries](../../docs/research/private-continuations.md)
and [verification record](../../docs/verification/private-continuations.md).
Paired-world tests are bounded witnesses, not an unbounded noninterference
proof. The original S1–S7 finite model is **not extended to this crate**.

Before production use, integrate authenticated rule approval, fact-service
transports, current descriptor/manifest checks, G1–G7, existing action approvals,
real provider execution and process isolation. The existing kernel accepts none
of this crate's roots or requests as new authority today. It is not appropriate
to call the `ProviderTransport` hook directly from the current product to bypass
those steps. General natural-language contract compilation, arbitrary generated
answers, mutable directory updates and real LLM utility studies remain unbuilt.
