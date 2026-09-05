# Intent-bound execution: implementation evidence

Snapshot: `codex/intent-bound-execution`, 2026-09-05. This supersedes intermediate
checkpoints in the plan. These are engineering checks, not attack-success or
performance experiments, a formal proof, or production/hardware readiness.
No install, service reset, credential change, push or deployment was performed.

## Implemented boundary

Final code snapshot: **73e0684**. The subsequent paper/documentation-only commit
does not change this tested production snapshot.

1. Authenticated original input and context feed a bounded structured draft.
   Native issuance verifies source/principal/task/deployment/revision. A separately
   approved draft can install/amend authority; action approval cannot enlarge it.
   Model output is never a signed grant.
2. The kernel matches a complete alternative, not a Cartesian product of allowed
   fields. Candidate completeness is relative to the entire bounded contract, not
   the universe of runtime data/tools. Seven typed control selections are separate
   from ordinary READ-limited provenance. Endorsement requires verified evidence.
3. ContentDigest precedes approval; AuthorizationDigest binds all endorsements and
   current task transition. Atomic prepare rechecks and commits task consumption,
   approval consumption and dispatch binding together. Replanning/new runs do not
   reset durable task budgets.
4. New task-bound tool dispatch resolves exactly one active registered connector
   through its exact signed descriptor. Its `provider_identity_digest` must equal
   the connector ID (including name/tier/transport); the business profile pins the
   real URL/TLS identity and credential slot. Missing/inactive/renamed/duplicated/
   removed routes fail closed. No destination-digest routing fallback on this path.
5. Closed codecs bind actual resource/destination/parameters/magnitude/payload/turn.
   The executor checks the worker frame before recording a provider attempt. The
   transport remains an eleven-field CBOR application frame over mTLS, **not a
   general HTTP/MCP client**. Logical bodies support reviewed fixed POST or closed
   JSON-RPC tools/call profiles, not arbitrary third-party schemas.
6. Signed terminal evidence binds authorization and retained response. The reviewed
   classifier, not worker success, determines known success. Failure/unknown cannot
   unlock success dependencies. Attempts are permanent; only explicitly permitted
   verified no-effect refund restores magnitude once. Historical reconciliation
   after expiry never authorizes another effect.
7. Verified tool results have separate task/run/commit-bound vault identities.
   Several results coexist with immutable original input. Exact replay is
   idempotent; changing content at a commit is refused, including after reopen.
8. Native handles are recorded before uncertain dispatch IPC. Same-ticket retry
   returns the exact handle without send/charge. After durable result/outcome commit,
   terminal success is cached before cleanup ACK so a lost response cannot erase it.
9. Context/editor and Rust/Python SDK transport bounded data/opaque handles, not
   trusted authority constructors. OpenClaw reserves the real receiver turn before
   input, scope approval and planning. Invalid/denied/pending scope does not plan.

## Integrated evidence (not a live product experiment)

`native_tool_dispatch_requires_registered_exact_profile_and_query_identity`
runs actual input-owner authentication, native issuance, planner prepare/commit,
proposal/evaluation, task-bound atomic prepare, signed/encrypted Suite1 IPC,
ExecdProtocolService, effect gate, encrypted journal, worker-frame verification,
retained-response classification, vault commit and completion ACK.

| Case | Observation |
| --- | --- |
| Exact registered request | One controlled provider attempt; success |
| Missing connector | Refusal before charge; zero provider attempts |
| Correctly signed worker changes recipient | FailedNoEffect; zero attempts |
| Provider failure | Indeterminate; one attempt, no success dependency |
| Dispatch ACK lost, executor reopened | Same handle; verified success; one attempt |
| Renamed connector retains old descriptor | Refusal before charge |
| Duplicate/renamed route | Refusal before charge |
| Two-step task with dynamic replanning | Step 2 initially refused; step 1 success permits fresh plan for step 2; another replan cannot reset either budget |
| Completion ACK processed, reply lost, executor reopened | First query errors; next returns committed success without provider retry |

`native_final_release_checks_real_executor_provider_and_lost_acknowledgement`
runs seven cases: success, changed turn, provider failure, unknown response,
lost dispatch ACK, lost dispatch ACK plus executor reopen, and lost completion ACK.
Actual original input/vault bytes, generic consent plus separately signed exact
TaskActionApproval and G7 over raw plaintext are used. The earlier scripted
unavailable case remains. Release supports the owned original up to 32 KiB,
**not arbitrary synthesized agent output**.

Fixture boundaries: provider and worker are controlled **in memory**. Encoding,
signatures, executor transitions and encrypted file reopen are real, but this is
not OS sandbox/TLS evidence. Input uses synthetic authenticated evidence through
the private owner boundary; approval proofs are fixture-created. Real approvald
ceremony and browser behavior are separate component checks, not a live hardware
ceremony. Rollback anchors are in-memory compare-and-advance fixtures.
`intent-bound-test-support` is absent from defaults and forbidden in non-debug
builds by compile_error.

## Bounded model and recovery

The separate accounting oracle explores 1,440 two-attempt traces: two clauses,
two alternatives, an invalid tuple, five first outcomes, three encrypted-owner
reopen positions, stale/current matches and reused/fresh approval nonces.
Observed: 984 admissions, 1,896 refusals and six distinct accounting observations.
This is a finite accounting projection, not exhaustive scheduling or a full-kernel
proof. Existing fault hooks also cover issuance/prepare uncertain commit, durable
rename boundaries, replay, stale revisions, concurrency and one-time refunds.

## Verification record

Use bundled Node in PATH for browser tests; the host Homebrew Node has an unrelated
missing library. Socket/subprocess tests use local test permission and temporary
paths. Locally rebuilt Python extension was not installed.

```sh
CARGO_INCREMENTAL=0 cargo test --locked --workspace -- --test-threads=2
CARGO_INCREMENTAL=0 cargo test --locked --workspace --features \
  savana-kerneld/test-support,savana-kerneld/macos-development-authority,savana-execd/openclaw-release-test-support,savana-platform-identity/test-support \
  -- --test-threads=2 --skip exact_replay_boundary_never_evicts_live_security_state
sh tools/check-frozen-v2-core.sh
sh tools/tests/check-frozen-v2-core.sh "$PWD/tools/check-frozen-v2-core.sh"
git diff --check
```

| Check | Observed result |
| --- | --- |
| Native library with test-support/development authority | 316 passed |
| Protocol full suite | 248 passed |
| Executor library / connector registry / isolation | 53 / 9 / 2 passed |
| New strict route activity/removal regression | Passed |
| New encrypted multi-result vault/replay regression | Passed |
| Python SDK, bridge, runtime, receiver after extension rebuild | 61 passed; six existing Python 3.14 deprecation warnings |
| OpenClaw TypeScript plugin with pinned installed dependency | 65 passed, nine files |
| V2 snapshot/checker adversarial tests | Passed; 220 paths; negative fixture diagnostics expected |
| Final default workspace run | Passed, exit 0; two test threads; one launchd-prerequisite test ignored |
| Final feature workspace coverage | Sequential rerun passed, exit 0; one already-passed replay test filtered, one launchd-prerequisite test ignored; see below |
| Final policy library / vault library | 232 / 8 passed |

First full feature run failed a rollover client health request with Unavailable
while server returned Ok. Isolated check passed (0.13 s). Inspection found a single
two-second deadline shared across cryptographic/socket exchanges. The test fixture
now uses fresh bounded deadlines and more scheduling time; production timeout
rules are unchanged. The failed run is not counted as passed. Final reruns determine
closure. The checker self-test initially lacked its required path argument;
the corrected invocation passed. Neither failure was suppressed/skipped.

A subsequent full feature run passed all 11 attack-matrix tests (308.48 s), but
four later lifecycle tests exited 64 because a concurrent default-feature build
replaced the shared target/debug daemon. This was a test orchestration error:
the fixture copies CARGO_BIN_EXE_savana-kerneld, whose test-only entry point is
absent in the default binary. The configurations are now run sequentially.
The final feature command omits only that already-passed five-minute replay test;
its same-snapshot evidence is retained from the full attack-matrix invocation.
No unexecuted test is counted as passed; no claim of a single clean unfiltered
feature-workspace invocation is made. The default workspace invocation is clean.

V2 hashes cover reviewed changed paths and new task wire/issuer/control/execution
sources. They detect source changes, not complete TCB coverage or release trust.
V1 frozen assets remain unchanged. No production materializer was executed.

## Paper verification (2026-09-05)

The revised [paper](../../paper/usenix-sec27/main.tex) and
[build instructions](../../paper/usenix-sec27/README.md) describe code snapshot
73e0684. The user's original LaTeX attachment was read and left unchanged.
The [Chinese summary](../academic-summary.zh-CN.md) replaces outdated measurements
and absolute guarantees; the older August paper/report are marked historical.

From paper/usenix-sec27:

~~~sh
latexmk -pdf -interaction=nonstopmode -halt-on-error \
  -outdir=../../tmp/pdfs/usenix -jobname=savana-intent-bound main.tex
~~~

Final build passed with TeX Live 2025, latexmk 4.86a, pdfLaTeX and BibTeX.
The result is ten letter-size pages, with all citations and labels resolved,
no overfull boxes and no draft insertion markers. All ten pages were rendered
at 110 dpi and visually reviewed, including tables, formulas and bibliography.
Underfull line/page advisories remain; they were visually reviewed, not hidden.
Text extraction confirmed nonempty pages, no unresolved citation marker and
glyph boxes clear of page edges. This is a clipping check, not template
certification.

The initial build caught a math macro used outside math mode; ensuremath and
short digest notation fixed it. Initial text-bound diagnostics used the nominal
text baseline box and flagged 2.2-point font descenders. The final clipping check
uses actual page-edge clearance, alongside visual inspection; margins/fonts were
not shrunk to satisfy it.

Generated output: output/pdf/savana-intent-bound.pdf (ignored build artifact).
SHA-256 of the delivered build:
dcfa8795133b741cb9243ad00d4917beb61631303098cda74b94229b31976cd7.
The hash identifies this rendered file, not bit-for-bit reproducibility across
TeX versions/timestamps or a signed release.

Primary citations were checked for CaMeL v2, Fides v2, Progent v3,
PCAS v1/FORGE v3, IGAC v3, CapAgent and classical checked endorsement.
The current Security '27 CFP was checked. Official style download returned 403;
the bundled fallback remains explicitly a working-draft approximation.
Empirical evaluation, anonymous artifact packaging and final official-template
validation remain submission work, not completed experiments.

## Residual limits

- Full **kerneld** restart does not restore opaque execution/session query handles.
  Task grants, accounting and dispatch records are durable; unresolved work fails
  closed rather than gaining a budget. Automatic whole-workflow resumption is not
  claimed. Executor reopen and durable authority recovery are separately tested.
- Never-delivered cleanup ACK may retain executor artifacts. There is no autonomous
  cleanup retry queue; same-owner observation is preserved, not universal
  availability or distributed exactly-once effects.
- Host product must implement the private broker task.draft exchange. Live browser/
  OpenClaw/hardware deployment was not exercised or certified.
- Only reviewed bounded codecs and structured authority are supported: no general
  natural-language intent compiler, semantic privacy guarantee, provider-internal
  semantics guarantee, malicious-destination defense or side-channel proof.
- TCB includes issuer, approval service, profile publisher, kernel data plane,
  executor supervisor and platform/deployment/credential trust, not just a small
  Rust module. Hardware-root prerequisites and platform-specific ignored tests
  remain explicit.
- Attack success, benign utility, approval burden and performance require separate
  experiments with denominators/baselines/artifacts. Regression counts are not
  empirical security or usability results.
