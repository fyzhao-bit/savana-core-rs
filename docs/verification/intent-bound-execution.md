# Intent-bound execution: implementation evidence (in progress)

This is an engineering checkpoint, not an experimental evaluation or a claim of
whole-system completion. Worktree: `codex/intent-bound-execution`; native release
checkpoint `e23c9c3`, followed by authenticated recovery changes. No push, install,
service reset, or production credential change was performed.

## Latest checked components (2026-09-05)

| Scope | Observed result | What it does not prove |
| --- | --- | --- |
| `cargo test --locked -p savana-kerneld --lib --features test-support,macos-development-authority` | 313 passed | Whole issuer-to-provider completion |
| `cargo test --locked -p savana-policy-core --lib` | 230 passed | An unbounded proof of all task traces |
| `cargo test --locked -p savana-ingressd --lib` | 21 passed | A real user hardware ceremony in the running deployment |
| `cargo test --locked -p savana-kernel-protocol` | 245 passed | Correct provider-internal interpretation of requests |
| `cargo test --locked -p savana-client` | 89 passed | Live OpenClaw integration |
| Python `test_client_sdk.py` against the locally rebuilt extension | 16 passed | Installed application behavior |
| V1 replay boundary in isolation | Passed, 305.18 s | A clean whole-workspace run; earlier runs had intermittent expiry/frame failures |

Protocol browser tests require the bundled Node runtime in `PATH` because the
system Homebrew Node installation has a missing dynamic-library dependency.
Socket fixtures ran with local test-network permission, using temporary paths.
Python 3.14 reports the existing `asyncio.iscoroutinefunction` deprecation warning.
The extension was linked locally with `-undefined dynamic_lookup`; no package was
installed. Crash-hook subprocess panic messages in the policy suite are expected
checks and are not omitted failures.

## Binding evidence

- Native final release uses actual owned source input, the current authenticated
  draft and committed plan, and one uniquely matched complete release alternative.
  The original source remains mandatory provenance. Unsupported/ambiguous mappings
  fail closed; current release payload support is the owned original document, not
  arbitrary synthesized agent output.
- Generic final-release approval alone, or a separately signed action proof for
  different content, is rejected without consuming the approval. The exact proof
  succeeds. G7 keeps leak checks over raw vault plaintext, not its base64 encoding.
- The native fixture captures a real authenticated Suite1 dispatch, independently
  verifies its signature, decrypts it and checks exact capsule content/turn/core.
  The fixture executor returns `ServiceUnavailable` after dispatch admission. No
  real provider effect or success is asserted by that test.
- Atomic task prepare rejects destination/evidence cross-binding before charging.
  The pre-fix behavioral test accepted the mismatched request; the corrected path
  refuses it and retains zero consumption. Policy fixtures were corrected to use
  evidence, rather than the adjacent payload-digest field.
- The release receiver accepts only the closed application-turn-bound request for
  its reservation and acknowledges after durable claim. Historical legacy claimed
  records remain readable/reconcilable but do not authorize new legacy delivery.
- Recovery destroys the input owner, reopens the encrypted task state, and checks
  fresh authentication against task/principal/manifest/generation/time. Wrong
  identities, unknown issuance IDs, expired authentication and revoked grants are
  refused. Existing receipt/display recovery leaves the rollback-protected head
  unchanged. Recovery proof cannot be reused for new structured issuance.
- The browser recovery control checks correlated receipts and opens independent
  task approval; it never commits approval implicitly. SDK recovery performs a
  fresh credential flow without begin/chunk/finalize or new issuance operations.

## Still required before code/paper closure

1. Trusted task-context discovery and contract creation/editor, including stable
   observation of pending issuance identifiers.
2. Reviewed production business profiles derived from actual target, pin and
   credential identities, with generator/config tests and no placeholders accepted.
3. OpenClaw receiver reservation before contract approval and planning, binding the
   real application turn rather than assigning the next result afterward.
4. Real integrated issuer → planner → proposal → approval → atomic prepare → execd
   → controlled provider tests, including adversarial and recovery cases.
5. Independent bounded transition exploration and its actual bounds/state counts.
6. Fresh whole-workspace and feature/security verification, reviewed V2 frozen
   manifests, and final code review. V1 production assets remain frozen.
7. Only then revise the paper from the user's immutable LaTeX draft. Unmeasured
   experiments must remain explicitly unmeasured; no acceptance score is implied.
