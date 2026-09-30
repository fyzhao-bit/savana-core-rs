# Result-dependent private loop (batch 43)

## Implemented boundary

The owner-clock private workflow now executes a finite, registered result-data
chain, not merely a list of actions with prefilled arguments. A successful tool
response can become a later operation's `body` without passing through Python,
Agent, Planner, or an externally supplied value handle. Initial input pinning,
signed profile/recipe admission and the authenticated private session are still
prerequisites. This adds no public RPC and activates no cloud model.

Policy schema 2 adds an optional binding:

```json
{"argument":"body","slot":[4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4],"result_of":1}
```

Operation 2 must list operation 1 in `after`. All registered orderings must place
the source before the consumer. Self/foreign sources, conflicting slot origins,
schema-1 result edges and result bindings to `to`/`file` are rejected. At G7 the
signed tool descriptor must also classify the actual destination field as
`Payload`; naming a control field `body` cannot evade that check.

Recipe schema 2 explicitly signs the profile, the immutable initial-input
snapshot digest and the precise source/consumer binding. The initial snapshot
therefore pins static destinations and resources even when a later payload is
not known yet. Schema-1 exact recipes do not implicitly approve future outputs.
The private host obtains `ActiveFusedPlanV04::input_commitment()` and the authoring
side uses `FusedRecipeApprovalV04::result_recipe`; neither is a model permission.
Existing signed administration transports the new typed approval unchanged.

## Actual execution order

1. Compile only the current ready operation. Future result slots have abstract
   plan positions but no fabricated local values or handles.
2. Run current G4, G5, any required exact G6 approval, G3 execution handoff and G7.
   Charge the original root and send the sealed request through authenticated
   local IPC to execd. Every later step repeats these checks.
3. Query/fetch the original execution. Verify the executor receipt, exact result
   digest and signed task outcome. Commit the result to the private vault and
   reconcile accounting.
4. For a declared downstream source, persist its raw value and provenance
   atomically with its result checkpoint in the encrypted, rollback-protected
   policy state. Only then acknowledge executor cleanup. A crash before this
   checkpoint leaves the original execution queryable; it is not a new attempt.
5. Reconstruct a deterministic local result identity on demand. The closed G3
   `DecodeUtf8` operation (tag 7) checks strict UTF-8, preserves bytes, parent
   evidence and the private/untrusted labels. It is not declassification,
   endorsement, semantic parsing or lossy repair.
6. Compile the next operation against that exact value/provenance/slot identity.
   Approval binds its now-concrete action. Unknown outcomes have no result slot
   and block the dependent action without refunding or resending the predecessor.

Recovery validates task/run/manifest, source action and execution nonce,
producer, lifetime, descriptor payload role, exact argument digests and the
original signed recipe. A successor cannot outlive its source input. Reopening
the encrypted owner does not reset budget or replace the source execution ID.
Historical validation uses the original admission time, not the restart time.
Records are retained for validation; there is no new result garbage collector.

## Concrete test example

The three-step fixture explicitly authorizes A→Alice, B→Bob and C→Carol, once
each, with signed predecessor-success dependencies and an overall quota of 3.
Step 1 sends its pinned text. Its actual synthetic MCP response, including that
request's unique ID, becomes step 2's body. Step 2's different response/request ID
becomes step 3's body. Assertions inspect the requests actually received by the
test provider, not a separately reconstructed ideal trace. The original two-call
quota refused step 3 until the *test fixture's* explicit authorization was enlarged;
production defaults were not changed.

The fixture also runs the executor cleanup-confirmation turns separately, as the
production fair recovery queue does. Completion ticks do not restart the chain.

## Bounds and non-claims

- Finite predeclared operations, existing 64-operation limit, existing 256-slot
  input bound. No arbitrary model-created steps or secret-dependent new model
  feedback channel, no unbounded autonomous loop, no new replacement theorem.
- Whole UTF-8 response → `body` only. JSON-field extraction, arbitrary destination
  selection from a response, binary transforms and result-based branching are
  not supported by this profile.
- Each retained encoded value and provenance is bounded to 32 KiB; aggregate
  retained result value/provenance is bounded to 256 KiB per task. Oversize,
  malformed or expired data fails closed. Terminal results with no consumers
  keep the existing result path and do not acquire this retention limit.
- An effect result is private execution data, not a user-visible publication
  grant or planner observation. Installation, private reauthentication after
  restart, exclusive publication/reconnect and hardware acceptance remain
  separate product gates. No live installation or AWS action occurs here.

## Reproducible checks

```sh
cargo test --offline --locked -p savana-kerneld --lib --features test-support fused_result_loop -- --test-threads=1
cargo test --offline --locked -p savana-continuation-core --test planning
cargo test --offline --locked -p savana-policy-core --lib result_utf8
cargo test --offline --locked -p savana-policy-core --lib result_recipe
PYTHONPATH=experiments python3 -m savana_bench regressions
```

Six real-kernel integration cases cover two/three-step byte flow, encrypted owner
reopen, exact second-step approval, revocation and Unknown. Five focused tests
cover closed model output, invalid dependency/slot bindings, signed initial-input
commitment, strict conversion and preserved private lineage. They use synthetic
sessions/keys/provider and a test rollback anchor: neither model success rates nor
hardware/installed-product acceptance may be inferred from these passes.

Validation (2026-09-21): macOS kernel 405/405, policy 416/416, continuation 50/50;
offline ARM Linux loop 6/6, related policy 5/5 and planning 16/16. The Python
selector passed 56/56 exact Rust cases; Python tests passed 46/46 without skips
using the rebuilt Rust driver. The workspace all-target check and 313-file
source-fingerprint check passed. Test totals overlap and must not be added into
a benchmark success rate. The browser test needed a working bundled Node because
the host Homebrew installation cannot load its dynamic library. A separate
cleanup-permission regression ensures denied process-group cleanup fails closed.
