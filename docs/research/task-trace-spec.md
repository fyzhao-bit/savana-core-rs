# Independent task-trace specification

Version 1, 2026-09-05. Research model only. Production reference: 73e0684.
This specification replaces the circular definition “safe means all Savana
checks passed.” Its authority and effect history are defined independently of
the implementation-shaped transition system.

## 1. Observation boundary and non-goals

A task has a principal/installation/task identity, independently authenticated
contract revisions, and a finite family of execution identities. The observer
sees task-purpose authority events, action-purpose approvals, durable reservation
commits, actual-request fences, application-level transport attempts, retained
responses, classified completion, policy settlement and completion ACKs.

An attempt means invocation of the monitored application transport with the
checked request. It is not a TCP packet, a guaranteed remote delivery, or an
exactly-once provider-internal business effect. A provider may have acted when
the local result is unknown.

The specification does not infer a user's unstated intent, assert that a human
understood an approval, prove noninterference, or require a useful answer. An
adversarial choice already allowed by the authenticated contract remains legal.

## 2. Independent state and authority inputs

Let C_v be the authenticated contract revision v. Each stable clause j declares:

- a finite relation R_v,j of complete action tuples;
- an attempt bound A_v,j and total magnitude bound M_v,j;
- predecessor clause identities D_v,j;
- whether a proven pre-effect failure refunds magnitude.

The full implementation tuple includes tool descriptor, codec, effect, resource,
destination, parameters and magnitude unit. The finite model varies resource,
recipient and profile; other fields are fixed. Every reservation has unit
magnitude. There are no runtime-discovered resources in this model.

The authority input sequence is explicit fixture data, not produced by the
planner or reconstructed from accepted actions. A task-purpose issuance or
amendment installs the next independently authorized contract. An action approval
may sign a proposed choice but cannot add a tuple to this sequence.

The specification observer records immutable reservations H, actual attempts E,
response/certification observations O, and approvals B. The implementation model
instead maintains mutable counters and owner states. It never calls the
specification to decide admission.

Each reservation h retains its execution identity, clause, whole action, original
contract revision, semantic epoch and terminal status. Consumption is derived
from history, not from implementation counters:

~~~text
Attempts_j(H) = number of distinct reservations for clause j
Magnitude_j(H) = sum over reservations h for j of
                0, if h has verified NoEffect and C_at_reserve(h) permits refund
                magnitude(h), otherwise
~~~

Refunds do not erase reservations. In particular, Pending, Started, Success and
Unknown all remain charged. A later amendment cannot retroactively authorize a
refund that the reservation's original contract forbade.

The pre-state version changes on new reservation, first settlement/start,
amendment and revocation; duplicate receipt/replay does not change task state.
The semantic completion epoch changes only when clause identities, alternatives
or dependency structure change. Numeric-limit-only amendments preserve it.
An A → B → A semantic amendment is two epoch changes, not revival of old success.

## 3. Prefix invariants

The permitted language L(C) is the set of finite event sequences whose every
prefix satisfies S1–S7 below. The definitions use historical authority/events,
not the boolean returned by the implementation model.

| ID | Required property |
| --- | --- |
| S1 Authority origin | Every installed root/revision is from the explicit authenticated task-purpose input sequence. No new reservation follows revocation. Action-purpose evidence never becomes a task root. |
| S2 Binding and currency | A new reservation selects one whole tuple in the current clause relation and has action evidence binding that exact tuple and current pre-state. Every actual-request fence/attempt equals its immutable reservation, including the pinned profile. Replay does not replace the action. |
| S3 Conserved consumption | Each new reservation keeps history-derived attempts and magnitude within the current bounds. Durable counters equal the history-derived values. Attempts never refund; only verified, originally permitted NoEffect removes magnitude, once. Amend/reopen/replay cannot erase consumption. |
| S4 Grounded dependency | At a successor reservation, each predecessor has a settled verified success from a reservation in the current semantic epoch. Neither Pending, Started, Unknown, NoEffect nor a pre-amendment success substitutes for it. |
| S5 Grounded outcome | Success settlement is backed by an observed, retained, correctly classified response and exact-execution completion evidence. A worker assertion alone is insufficient. NoEffect is established before a possible effect; terminal state cannot change on replay. |
| S6 No automatic resend of a reserved execution | For every execution identity, the monitored transport-attempt count is at most one, including across restart. This does not promise that the remote side acted once or that a task with an explicit larger budget cannot issue another legitimate execution identity. |
| S7 Commit-before-ACK | Completion ACK occurs only after the policy outcome has durably committed. The native implementation additionally commits the owned result first. The two-owner model does not represent vault insertion as a separate owner. |

S1 is deliberately **prepare-linearized revocation**, not “no packet may leave
after revoke.” An immutable reservation committed before revoke can still
attempt and reconcile under its original evidence. Recovery and historical
settlement are not new task authority.

## 4. Abstract transitions and linearization

| Transition | Required authority/observation | State effect |
| --- | --- | --- |
| Issue / Amend | Authenticated task-purpose input | Install declared revision; retain all consumption; update semantic epoch when necessary |
| Approve | Authenticated action-purpose evidence | Bind a candidate and a pre-state; does not reserve or widen authority |
| Reserve | Whole tuple, current evidence, available history-derived budget and predecessor success | One atomic policy-owner commit of immutable binding, consumed approval and charge |
| Replay | Exact previously reserved identity/content | Return historical association; no new charge or request |
| Fence | Actual request/profile equality under a verified dispatch | Persist attempt fence; create a live one-use continuation |
| Emit | Matching live continuation | Invoke the monitored transport once; response may be received or lost |
| Retain | Observed response from this invocation | Persist response; not yet permission to unlock a successor |
| Certify | Retained response satisfies reviewed success semantics and completion verification | Make exact-execution success evidence available |
| NoEffect / Unknown | Verified pre-effect failure / conservative uncertain outcome | Make the corresponding terminal evidence available; Unknown may follow retained-response decode failure |
| Started / Settle | Exact-execution evidence | Atomically reconcile task/dispatch/accounting; terminal-first success is allowed |
| ACK | Already committed success and trusted kernel-side ordering | Acknowledge completion; does not delete the reservation or authorize another send |
| Crash / Reopen | Owner restart under valid durable state | Preserve authority history; lose executor live continuation and unretained response |

Fence abstracts two executor journal commits: ProviderAttemptPrepared and
EffectStarted. Neither recovered state permits a new send. A crash at either
point is represented by Fence → Crash → Reopen → Unknown with zero observed
transport invocations possible. This is a conservative selected abstraction,
not a verified simulation of every intermediate Rust state.

Retained response and terminal success are separate model steps. A retained
response can be decoded/verified after reopen, or conservatively lead to Unknown;
it cannot justify resending the original request.

Missing acknowledgements are represented by delaying the next observation and/or
crashing between durable events. Duplicate replay and terminal receipts are
explicit self-loops. Unobservable dropped messages are stuttering steps; there
is no explicit unbounded network queue or fairness/liveness proof.

## 5. What the checker actually establishes

The executable implementation-shaped machine is model.py. The independent
observer is spec.py. domain.py contains shared fixture declarations and the
event vocabulary only; it contains no shared admission predicate.

The checker explores the product (implementation-model state, specification
history) with breadth-first search. For every enabled transition it folds the
external event through the specification and compares the durable policy
projection to history-derived consumption and outcomes.

If any prefix fails, it returns the first shortest counterexample in that
scenario. If the work queue empties, every reachable state and outgoing edge in
that finite product graph has been checked, including arbitrarily repeated
cycles in this graph. If the state cap is reached it returns “incomplete” and a
failing exit code, never a successful safety result.

This establishes finite **model-to-spec** conformance under the stated input
domains. It is not a mechanized refinement from Rust to the model, a proof for
unbounded task sizes, or verification of signatures, IPC, parsers, storage,
platform isolation or provider semantics.

### Conditional argument, not an unbounded machine-checked theorem

For the abstract transition rules, an induction can be organized as follows.
Initially the authority and reservation histories are empty. Issue and Amend
have independent task-purpose authority and preserve consumption. Reserve adds
one history entry only after checking the current relation, evidence, bounds
and predecessor witnesses. Fence binds one immutable request; the only live
continuation is consumed by Emit and is destroyed on crash. Retain/Certify
construct outcome evidence from the observed response. Settlement changes no
history entry's identity and only applies the original refund rule. ACK and
recovery do not mint authority.

Each case has a specific preservation obligation; the finite explorer checks
instances of these cases and their compositions. The argument is conditional on
these transition rules being implemented and on the assumptions below. The
production correspondence table is an audit aid, not a discharged proof.

## 6. Bounds, assumptions and explicit omissions

The committed run uses 11 separately exhausted scenario graphs. Configurations
have one task, one or two clauses, one to three fixed execution identities,
one to three explicitly authorized contract revisions, unit magnitude, at most
two allowed attempts per clause, and fixed finite action/profile choices.
The graphs exercise relations, a one-winner race, stale approvals, dependencies,
semantic epoch and ABA changes, numeric amendments, retry limits, two-owner
recovery, a lost attempt fence, and prepare-linearized revocation. They are
separate configurations, not one simultaneous all-feature graph.

Assumptions include:

- Correct authenticated task input; unforgeable domain-separated evidence and
  unambiguous identities/canonical encodings.
- Complete mediation by trusted owners/transport; no alternate network or
  filesystem authority available to a hostile worker.
- Sound reviewed request/response profile and provider identity mapping.
- Atomic durable commits and a correct monotonic recovery anchor; uncertain
  commits cannot release new authority until safely reopened.
- ACK ordering is enforced by the trusted native kernel caller. Execd checks the
  authenticated request binding but does not independently inspect the policy
  owner's disk or prove a nonzero commit digest is durable.

Not represented: multiple principals/tasks, cross-task nonce collisions, real
time/expiry, registry revocation and deployment-generation races, hash/signature
algorithms, byte parsers, seven individual control-plane records, clause removal
tombstones, variable magnitude/overflow, torn filesystem states, malicious
rollback anchors, separate vault commits, or all native session handles.
Several have Rust tests, but those tests do not expand this model's theorem.

## 7. Evidence links

- [Run instructions, bounds, counts and witnesses](../../verification/task_trace/README.md)
- [Specification implementation](../../verification/task_trace/spec.py)
- [Finite transition system](../../verification/task_trace/model.py)
- [Committed, source-hashed generated results](../../verification/task_trace/results.json)
- [Rust boundary correspondence and remaining obligations](task-trace-rust-map.md)
- [Closest work and non-composition counterexamples](task-authority-positioning.md)
