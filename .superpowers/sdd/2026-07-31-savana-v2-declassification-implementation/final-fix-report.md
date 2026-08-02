# Savana V2 declassification final security-fix report

Date: 2026-07-31

Scope: final review findings in `final-review-findings.md`, against the accepted
implementation plan and `docs/declassification-v2.md` v1.1.

## Outcome

All seven final-review findings are implemented. The production security paths
remain fail-closed, canonical wire validation remains exact, the new active
declassification-policy module is included in the frozen V2 boundary, and the
final verification matrix passes.

## Finding 1: final-release consent atomicity and replay

Changes:

- Removed in-memory `Cell<bool>` consumption from
  `VerifiedFinalReleaseSettlementV2`; declassification validation is now pure.
- Bound destination, token scope, active manifest, issuance, expiry, and rule
  maximum age into pure consent validation.
- Made settlement one-use enforcement part of durable final-release dispatch
  preparation. Exact WAL replay is accepted only when the release binding,
  settlement digest, ticket, sealed payload digest, and authority identity all
  match. The same settlement cannot authorize a different release, and the
  same release cannot replay under a different settlement.
- Bound the final-release declassification node digest with the exact plaintext
  in the durable preseal digest, preventing recovery from aliasing the same
  bytes to different provenance.

RED/GREEN evidence:

- `cargo test -p savana-policy-core final_release_consent_validation_is_pure_across_gate_failure_and_retry --all-features --locked`
  - RED: retry after a later gate failure returned `ConsentConsumed`.
  - GREEN: 1 passed; the blocked attempt leaves consent reusable, the safe
    retry succeeds, and exact revalidation succeeds.
- `cargo test -p savana-policy-core g7_final_release_wal_and_quota_survive_restart_without_aliasing_tool_attempts --all-features --locked`
  - RED 1: a distinct release using the same settlement returned a created
    preparation.
  - RED 2 (final self-review): the same durable release using a different
    settlement returned `Replay`.
  - GREEN: 1 passed; exact replay survives restart and both non-exact forms
    return `G4Error::StateConflict`.
- `cargo test -p savana-kerneld durable_preseal_binding_covers_exact_plaintext_and_declassification_node --all-features --locked`
  - RED: final-release preseal node-binding helper was absent.
  - GREEN: 1 passed; changing either plaintext or node changes the durable
    preseal digest.

## Finding 2: planner requests closed to signed policy

Changes:

- Added closed `PlannerPurposeV2::PlannerCall` protocol vocabulary and exact
  canonical request encoding/decoding.
- Derived route, task template, intent, purpose, and limits from the verified
  input-runtime planner envelope and retained them in durable claim recovery
  material and the live session.
- Kerneld now equality-checks route/template/intent/purpose and computes the
  componentwise minimum of requested and signed limits. Unsupported values
  cannot mint a planner ticket.
- The input runtime exposes only the verified signed planner fields; no raw
  input bytes are placed in the planner envelope.

RED/GREEN evidence:

- `cargo test -p savana-kernel-protocol --test v2_kernel_agent_wire planner_preparation_has_a_bounded_typed_value_list --all-features --locked`
  - RED: protocol request had no closed purpose field.
  - GREEN: 1 passed with exact canonical typed fields.
- `cargo test -p savana-input-runtime g2_is_closed_ambiguous_fail_closed_and_planner_bytes_contain_no_input --all-features --locked`
  - RED: verified route/template/limit accessors were absent.
  - GREEN: 1 passed.
- `cargo test -p savana-kerneld planner_request_is_closed_to_signed_policy_and_limits_are_intersected --all-features --locked`
  - RED: no signed planner-policy intersection existed.
  - GREEN: 1 passed; route, template, and intent mismatches are refused and all
    four limits are intersected server-side.

## Finding 3: declassification rule-set rollover and revocation

Changes:

- Added `ActiveDeclassificationRuleSetV2`, holding the verified trust roots and
  an `Arc<RwLock<Arc<DeclassificationRuleSetV2>>>` active snapshot.
- Candidate bytes are fully canonical-decoded, digest/signature/window/root
  verified, then checked with `validate_predecessor(Some(active))` under the
  write lock before one atomic pointer swap.
- Every failure leaves the old active set untouched. Runtime/data-plane callers
  share the holder and snapshot one coherent generation per operation.

RED/GREEN evidence:

- `cargo test -p savana-kerneld verified_successor_swaps_atomically_and_rollback_retains_active_set --all-features --locked`
  - RED: active rollover type/implementation was absent.
- `cargo test -p savana-kerneld v2_declassification_policy::tests --all-features --locked`
  - GREEN: 2 passed, covering a valid successor, rollback, invalid signature,
    invalid digest, invalid window, and active-set retention after every
    failure.

## Finding 4: gate before tool durable prepare/quota

Changes:

- Reordered tool execution so the exact dispatch plaintext is declassified and
  its handoff judgment admits before `prepare_verified_tool_dispatch` can run.
- Added a production ordering boundary whose durable-prepare closure is
  unreachable on gate failure.
- The durable preseal digest binds both exact plaintext and the returned
  declassification provenance-node digest.

RED/GREEN evidence:

- `cargo test -p savana-kerneld durable_preseal_binding_covers_exact_plaintext_and_declassification_node --all-features --locked`
  - RED: node-bound preseal helper was absent.
  - GREEN: changing plaintext or node changes the digest.
- `cargo test -p savana-kerneld rejected_execution_gate_leaves_dispatch_and_quota_unmodified --all-features --locked`
  - RED: the production gate-before-prepare boundary was absent.
  - GREEN: rejected gate returns before the durable preparation closure;
    dispatch remains `Authorized` and reserved quota remains zero.

## Finding 5: complete deployment trust includes declassification root

Changes:

- Added the declassification trust-root member-set digest to
  `ExpectedPreStateV2` canonical schema.
- Added the declassification chain to native bootstrap trust material and
  authenticated trust decoding.
- Threaded the exact declassification root object through complete-trust
  transaction creation/decoding and the durable transaction store.
- Staging now requires Declassification binding domain, product-family
  equality, expected member-set digest equality, and exact versioned identity
  equality with the bootstrap lock.

RED/GREEN evidence:

- `cargo test -p savana-policy-core --test v2_deployment_transaction_intent --all-features --locked`
  - RED: constructor/schema lacked the declassification root field.
  - GREEN: 4 passed.
- `cargo test -p savana-policy-core --test v2_operational_trust_root --all-features --locked`
  - RED: bootstrap material lacked the fourth trust chain.
  - GREEN: 4 passed, including missing chain, wrong binding domain, wrong
    family, and exact-version mismatch refusal.
- `cargo test -p savana-policy-core --test v2_security_state_manifest --all-features --locked`
  - GREEN: 7 passed with complete-trust closure.

## Finding 6: exact approval display artifact

Changes:

- Signed approval envelopes now carry bounded exact display bytes and the
  display declassification node digest. Construction and decoding recompute
  the display digest and require a nonzero node for non-ingress approvals.
- Approvald verifies and retains the canonical signed envelope, projects the
  exact bytes/node, persists them through recovery, and binds settlement to the
  signed envelope digest.
- Browser views carry, verify, canonically encode, and render those exact
  bytes. UI authentication remains bound to the same display digest.
- Tool and final-release approval paths carry only their exact display artifact;
  unrelated confidential bytes are not added.
- Self-review corrected signed approval decoding to use the approval-specific
  bounded payload cap rather than UI authentication's 8 KiB cap.

RED/GREEN evidence:

- `cargo test -p savana-kernel-protocol --test v2_kernel_ingress_success ingress_authentication_and_finalize_successes_are_typed_and_canonical --all-features --locked`
  - RED: signed approval schema lacked exact bytes/node fields.
  - GREEN: passed with exact canonical wire round-trip.
- `cargo test -p savana-approvald protocol_owned_approval_and_ui_envelopes_produce_exact_settlements --all-features --locked`
  - RED: approval projection exposed hashes only.
  - GREEN: exact bytes are projected; signed-payload tampering is refused as
    `InvalidEnvelopeSignature`.
- `cargo test -p savana-kernel-protocol browser_view_encodes_exact_gated_bytes_and_node_digest --all-features --locked`
  - RED: browser view lacked exact bytes/node.
  - GREEN: exact render bytes round-trip and non-ingress missing-node input is
    refused.
- `cargo test -p savana-kernel-protocol --test v2_kernel_ingress_success approval_signed_wire_round_trips_bounded_display_larger_than_ui_auth_limit --all-features --locked`
  - RED: a valid 16 KiB approval envelope decoded as malformed because the
    decoder incorrectly applied the 8 KiB UI-auth cap.
  - GREEN: exact 16 KiB signed-wire round-trip and signature verification pass.

## Finding 7: declassification-rule negative matrix

`crates/savana-policy-core/tests/v2_declassification_rules.rs` now exercises:

- exact top-level/nested canonical shape and EOF handling;
- independently recomputed payload and signed digests;
- signature tag/domain mutation and unauthorized signer refusal;
- purpose/transition ownership mismatch;
- illegal reader and consent shapes;
- zero, duplicate, and unsorted values;
- set/rule validity windows;
- predecessor success, missing predecessor, rollback, and fork refusal;
- compiled maximum rule and reader counts; and
- wrong trust-root binding purpose.

Evidence:

- Initial expanded run: 6 passed, 1 failed because the deliberately wrong-root
  fixture itself omitted the deployment root's required rollback member.
- After correcting only that fixture:
  `cargo test -p savana-policy-core --test v2_declassification_rules --all-features --locked`
  passed 7/7.

## Final verification matrix

- `cargo fmt --all -- --check` — PASS.
- `cargo clippy --quiet --workspace --all-targets --all-features --locked -- -D warnings` — PASS.
- `cargo test --quiet --workspace --all-targets --all-features --locked` — PASS, exit 0. The durable replay-boundary group passed 11/11 in 301.59 seconds.
- `cargo build --quiet --workspace --release --locked` — PASS (the repository's CI production release gate).
- `RUSTDOCFLAGS='-D warnings' cargo doc --quiet --workspace --all-features --no-deps --locked` — PASS after correcting two comment-only intra-doc link lints.
- `cargo test -p savana-platform-identity --test macos_worker_sandbox --all-features --locked` — PASS, 4/4 native macOS sandbox tests.
- `tools/check-frozen-v2-core.sh` — PASS after reviewed checksum regeneration.
- `sh tools/tests/check-frozen-v2-core.sh tools/check-frozen-v2-core.sh` — PASS; modified content, unsorted/duplicate entries, absolute paths, traversal, and missing files are refused.
- `git diff --check` — PASS.

The plan's broader `cargo build --workspace --all-targets --all-features --release --locked`
was also run. It intentionally returns exit 101 because `--all-features`
activates `macos-development-authority`, whose existing release-mode
`compile_error!` is a security guard. That guard was preserved. The exact CI
production release command above passes.

## Frozen-boundary review

Every changed path reported by the pre-update checker was reviewed before
regeneration. The new production modules
`crates/savana-policy-core/src/v2/declassification.rs` and
`crates/savana-kerneld/src/v2_declassification_policy.rs` are both explicitly
listed in `deploy/frozen-v2-core.files`; the regenerated checksum manifest
passes both the production checker and its adversarial test suite.

## Remaining concerns

No unresolved product or test failures remain. The all-features release refusal
is expected security behavior, not a regression. One native sandbox test emits
the platform helper's "native worker sandbox is unavailable" diagnostic while
testing its fail-closed resource-limit fallback; the four-test integration
target still passes.
