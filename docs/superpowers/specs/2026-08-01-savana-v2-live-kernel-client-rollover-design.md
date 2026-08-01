# Savana V2 Live Kernel Client Rollover Design

> Date: 2026-08-01
>
> Status: approved for implementation
>
> Fix round: Task 2, round 2 of 5

## 1. Problem and completion boundary

Kerneld can publish a verified generation successor without restarting, but an
already-running agentd or ingressd currently retains the exact generation-one
`KernelServiceHandshakeEdgeV2`. Suite One correctly requires exact transcript
equality, so the generation-one client and generation-two server reject one
another. Constructing a fresh client after publication does not exercise or
solve this live-client boundary.

This fix makes each agentd and ingressd Suite-One kerneld client a long-lived,
atomically reloadable holder of fully verified generation authority. The same
client object created before publication must complete a real Suite-One request
after kerneld publishes the immediate successor. Both daemons also prepare a
SIGHUP reload path so a supervisor can proactively align clients before new
traffic. A missed signal is repaired by one verified reload and one retry after
the live handshake rejects the old transcript.

This design does not weaken Suite-One transcript comparison, allow a stale
generation, add a downgrade path, or make a caller-supplied handshake edge a
reload authority. It does not make unrelated daemon subsystems generally
hot-reloadable.

## 2. Authority ownership

Each client is split into stable process context and generation authority.

Stable context contains the fixed kerneld socket, the daemon boot ID, the
already-pinned native process binding, the client signing key, the kerneld
public key, the kerneld boot ID, and the closed service edge identifier. These
values never change during a live generation rollover.

Generation authority is an immutable, redacted object held behind a shared
`Arc<RwLock<Arc<_>>>`. It contains the exact handshake edge and, for agentd,
the task-authority key identity and public verification key used by client
response checks. It also contains the continuity summary derived from the
fully verified startup: installation, manifest sequence and digest,
deployment generation, effect fence, protocol ABI, all six runtime identity
digests, the client and kerneld service locks, and the complete closed edge
lock including its listener identity and handshake key IDs.

`SuiteOneAgentKernelClientV2` and `SuiteOneIngressKernelClientV2` become cheap
clones of that shared holder. Agentd constructs one reloadable client and
clones it for the control dispatcher and browser authority, so both consumers
observe one atomic active generation instead of independently cached edges.
No public production API accepts a replacement edge or partially populated
authority.

## 3. Verified successor loader

Each daemon owns a private fixed-path successor loader. It rereads only the
platform's compiled-in bootstrap path with the existing bounded, regular,
single-link, ownership and mode checks; rejects a changed bootstrap shape; and
runs the existing complete `load_native_startup` verification. It then verifies
the exact bytes against that daemon's service-config digest in the candidate
startup.

The loader derives the candidate client authority from
`VerifiedDaemonStartupV2` and the stable process context. It does not reread or
rotate in-process secret credentials. Candidate edge key IDs must still match
the retained client signing key and kerneld public key. Agentd's retained task
authority public key and bootstrap key ID must remain exact.

Before publication, the candidate must satisfy every condition below against
the authority that is active while the write lock is held:

- the installation is identical;
- manifest sequence, deployment generation, and effect fence are each exactly
  the current value plus one, with checked arithmetic;
- protocol ABI and all six runtime identity digests are identical;
- the running client's service identity and kerneld's service identity are
  identical;
- the complete client and kerneld service deployment locks are identical,
  including executable/code, configuration, sandbox, socket, and platform
  authority identities;
- the complete edge lock is identical, including the listener identity,
  native peer expectation, role, services, and both handshake key IDs;
- the retained daemon and kerneld boot IDs and retained public-key bindings
  still produce the candidate edge; and
- for agentd, the retained task-authority key identity and public key remain
  identical.

Only the manifest digest and the three exact successor counters may change.
A reload based on a stale preflight cannot overwrite a concurrently installed
successor: continuity is checked again against the active value under the
write lock. If another thread has already installed the same successor, reload
is idempotent success. A rollback, skipped generation, same-generation
replacement, expired or badly signed manifest, partial publication, changed
runtime/listener/key/process identity, poisoned lock, or any I/O/verification
failure leaves the old `Arc` untouched and returns failure.

## 4. Request and retry semantics

Every request clones one generation-authority `Arc` under the read lock and
uses that immutable snapshot for the complete connection, including agentd
task-authority response verification. Reload never changes a request already
in flight.

The first connection attempt preserves exact Suite-One behavior. Only a
failure after the client hello has been emitted and before the server
handshake is accepted is classified as a possible authority mismatch. That
classification does not trust the peer: it merely permits the private loader
to attempt complete fixed-path successor verification. Connect failures,
application-record failures, decoded kernel errors, and deadline failures do
not trigger reload.

On a possible handshake mismatch, the client serializes reload attempts. If a
concurrent request already advanced the authority, it reconnects with the new
snapshot. Otherwise it invokes the full successor loader and publishes only a
valid exact successor. It then opens a new connection and retries the original
request exactly once. The second attempt never reloads or retries again. A
failed reload returns the original closed public error. Request IDs and
operation bodies remain stable across the retry, while the cryptographic nonce
and ephemeral key are freshly generated for the new connection.

## 5. Proactive SIGHUP lifecycle

Agentd and ingressd install SIGHUP handling before their worker/accept loops
start. A small private signal thread owns the signal iterator and calls the
same serialized verified reload path used by handshake recovery. Successful
reload atomically publishes the successor. Rejected reload is nonfatal to the
daemon, emits no authority details, and keeps the old generation active.

SIGTERM and other service-manager lifecycle signals keep their existing
behavior. Deployment definitions expose an `ExecReload` SIGHUP action where
the platform supports it; macOS uses the existing service-manager signal
mechanism. Signal handling does not create a second verification or publication
path.

## 6. Security invariants

- Server and client transcript equality remains byte-exact.
- The holder contains only authority derived from complete authenticated
  startup verification; production callers cannot inject raw successor state.
- Publication is one pointer swap after all fallible validation completes.
- Readers see either the complete old authority or the complete successor.
- An invalid candidate cannot destroy or partially mutate the active value.
- Successors are installation-local and strictly monotonic by one for all
  three counters.
- Process, executable/code, configuration, sandbox, listener, native peer,
  socket, key, protocol, and runtime identities cannot change live.
- A malicious or malformed server hello can cause at most one bounded local
  verification attempt and one retry; it cannot authorize a generation.
- Error surfaces stay closed and redacted.

## 7. Test and evidence plan

Strict RED tests first create real agentd and ingressd Suite-One clients while
kerneld serves generation one, prove a generation-one request, publish the
verified generation-two live bundle, and then use those same pre-existing
client objects for generation-two requests. The test must fail before the
client implementation because a fresh post-publication client is forbidden in
the post-rollover phase.

Focused client tests cover one retry only, shared-clone visibility, coherent
agent task-authority snapshots, and no reload after non-handshake failures.
Lifecycle tests cover proactive SIGHUP preparation and invocation. Atomicity
tests feed malformed, expired, rollback, skipped, partially published, and
identity-changing candidates and prove both that the old authority remains
selected and that subsequent generation-one service traffic still works.

Verification includes focused agentd/ingressd client and lifecycle tests, the
real kerneld rollover test, affected package suites, kerneld rollover/library/
startup/deployment suites, all-features checking, formatting and diff checks,
and one broader workspace-appropriate suite. Exact RED and GREEN commands and
results are appended under `## Fix round 2` in the existing Task 2 report.
