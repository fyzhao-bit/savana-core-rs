# Task-trace model checking (research only)

This is a finite, executable model-to-specification check. It is not linked into
Savana, does not change the Rust kernel, and is not a proof of the Rust runtime.
Read the [independent specification](../../docs/research/task-trace-spec.md),
[research positioning](../../docs/research/task-authority-positioning.md) and
[Rust correspondence](../../docs/research/task-trace-rust-map.md) before using
the results in a paper.

## Reproduce

Python 3.10+; standard library only. Run from the repository root:

~~~sh
python3 -m unittest verification.task_trace.test_check -v
python3 -m verification.task_trace.check \
  --check-recorded verification/task_trace/results.json
~~~

To intentionally regenerate the evidence after changing the model:

~~~sh
python3 -m verification.task_trace.check \
  --output verification/task_trace/results.json
~~~

Inspect the source and scope changes, not just the counts. The JSON contains
source SHA-256 values, every scenario's exact contract/candidate bounds, coverage
witnesses, explored event counts, and shortest mutant counterexamples. The CI
job regenerates and compares it; a stale report fails.

For a restricted run, use e.g. --scenario recovery --baseline-only.
--max-states sets a fail-closed resource cap, not a depth bound. Reaching it
reports “incomplete” and fails; it is never counted as verification success.
No unbounded liveness or fairness property is checked.

## Three distinct artifacts

| File | Role |
| --- | --- |
| domain.py | Fixed authority inputs and event vocabulary; no shared permission predicate |
| model.py | Implementation-shaped abstract policy/executor owners and separately selectable faulty variants |
| spec.py | Independent observer reconstructing authority, reservations, attempts and outcomes from trace events |
| check.py | Exhaustive BFS of each finite product graph, shortest counterexamples, positive-coverage requirements and generated evidence |
| test_check.py | Checker sanity tests, negative inputs, non-vacuity, refund limits, ABA and revocation witnesses |
| results.json | Deterministic generated evidence, not hand-entered experiment data |

The implementation model has mutable counters. The specification derives
counters independently from historical reservations and each reservation's
original refund rule. They share only declared input contracts and event types.
The source-independence test checks imports as a hygiene measure; an import test
is not a proof that the two implementations have no correlated mistakes.

## Committed finite run

2026-09-05: all 11 baseline graphs exhausted; no S1–S7 violation found.
The per-scenario sum is **11,788 reachable product states and 59,003 edges**,
including replay/self-loop edges. These are separate graphs, not one joint
all-feature state space; counts are not independent tasks or attack trials.

| Scenario | States | Edges | Scope |
| --- | ---: | ---: | --- |
| relation | 57 | 161 | Joint relation; crossed resource/recipient and wrong-profile choices |
| race | 195 | 677 | Two requests competing for one reservation |
| stale | 2,381 | 11,649 | Two-budget requests; stale pre-state evidence |
| dependency | 275 | 1,290 | Success-dependent successor, not worker assertion |
| epoch | 1,221 | 6,977 | One semantic amendment |
| epoch_aba | 2,776 | 16,344 | A → B → A without resurrecting old success |
| amendment | 1,030 | 5,131 | Numeric amendment preserves success and prior consumption |
| recovery | 1,405 | 5,417 | Separate owner restarts, retained/unretained responses, no-effect retry |
| retry_limit | 1,998 | 9,826 | Three candidate executions, two permanent attempts, refundable magnitude |
| lost_fence | 145 | 470 | One execution; crash destroys live continuation, not durable attempt history |
| revocation | 305 | 1,061 | Revoke blocks new prepare, not already committed work |

Fourteen checker tests pass. Each baseline is required to include successful
execution, terminal-first settlement, replay and ACK. Relevant scenarios also
require admitted dependencies, actual post-revocation execution of an earlier
reservation, retry after proven no-effect, amendment after consumption, and
retained-success reopen. A monitor that simply denies all requests fails these
coverage requirements.

## Fault variants and shortest counterexamples

Every variant weakens one stated obligation in the abstract machine. The
production code is untouched. All 11 variants are detected:

| Variant | Property | Shortest events |
| --- | --- | ---: |
| action_as_task_authority | S1: separate authority purposes | 1 |
| cartesian_membership | S2: whole tuple, not projections | 3 |
| split_check_commit | S3: atomic task reservation | 5 |
| stale_approval | S2: current action evidence | 5 |
| unchecked_request | S2: actual request equality | 4 |
| worker_asserted_success | S5: independently verified completion | 4 |
| old_epoch_dependency | S4: current-epoch predecessor | 11 |
| volatile_attempt_fence | S6: no resend after restart | 9 |
| refund_unknown | S3: unknown keeps its charge | 7 |
| reset_amendment_charges | S3: amendment retains history | 4 |
| cleanup_before_commit | S7: settle before completion ACK | 8 |

Minimality is only within that variant's explicit event vocabulary and finite
configuration. In particular, validation plus the two pre-transport journal
commits are abstracted as Fence, not three separate instructions. A combined
atomicity fault uses a captured check snapshot at commit; it is not claimed to
be a one-line Rust mutation.

These are constructional non-composition witnesses, not discovered exploits in
CaMeL, Fides, Progent, FORGE, IGAC or CapAgent. No comparative ASR, performance
or user-utility conclusion follows from the numbers.

## Limits that must accompany any citation of this run

One task; one/two clauses; one–three fixed execution identities and authenticated
contract revisions; unit magnitude; finite choices; two durable owner abstractions.
Root identity/crypto, all seven control-plane bindings, deployment/registry
updates, timestamps, byte codecs, filesystem corruption/rollback, separate vault
transactions and full kerneld session reconstruction are outside the graph.

The graph explores all enabled orderings in each declared abstraction, not every
interleaving in the real program. Duplicate/dropped replies are represented by
replay, delayed observation and crash cuts, not a detailed network stack.
Unknown outcomes can sacrifice availability; no provider-internal exactly-once
property or general natural-language intent fidelity is established.
