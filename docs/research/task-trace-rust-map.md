# Trace specification to Rust: correspondence and remaining obligations

Audit date: 2026-09-05; production source snapshot 73e0684. This is a manual
source/linearization map, not mechanically extracted Rust semantics. The new
Python checker executes an abstract machine, not the production Rust owners.
Existing Rust tests are complementary witnesses, not a proof of refinement.

## Transition correspondence

| Abstract event / invariant | Real owner and source boundary | Executable witness / remaining obligation |
| --- | --- | --- |
| Issue / Amend, S1 | [Native task issuer](../../crates/savana-kerneld/src/v2_task_authority.rs): issue_structured, attach_approval, settle_approved, install. [Policy issuance](../../crates/savana-policy-core/src/v2/durable.rs): record_pending_task_authorization and install_pending_task_authorization clone and commit one snapshot | task_amendment_needs_exact_expected_key_task_purpose_approval; pending issuance uncertain-commit test. Model assumes the authentication and complete user-approved draft are correct |
| Revoke, S1 | Native issuer revoke checks exact authenticated current draft. [TaskLedgerV2::revoke](../../crates/savana-policy-core/src/v2/task_state.rs) sets revoked and advances task state. New prepare calls context, which rejects revoked | task_revocation_requires_the_exact_authenticated_current_draft_and_never_regrants; durable identity/revocation test. Existing bindings and executor attempts are not retroactively canceled |
| Approval / joint relation, S2 | [Task authorization matcher](../../crates/savana-policy-core/src/v2/task_authorization.rs), [control selection](../../crates/savana-policy-core/src/v2/control_selection.rs), protocol task_action_approval/task_action_display | task_authorization_approval_is_content_bound_and_cannot_expand_contract; generation-change and settlement mutation tests. Seven distinct endorsements, CD/AD hash domains and shared settlement nonces are not separately modeled |
| Reserve, S2–S4 | [DurableG4StateV2::prepare_tool_dispatch](../../crates/savana-policy-core/src/v2/durable.rs): dispatch preparation, tasks.prepare, quota.reserve_or_replay and intent transition happen in a private snapshot under the current-registry guard, followed by one commit. Final release has the analogous path | task_state_concurrent_prepares_and_file_lock_have_one_winner; task_state_uncertain_commit_reopens_one_charged_reservation. The model assumes serialization/atomicity; Rust witnesses exercise the actual file owner and commit hooks |
| Semantic epochs / persistent consumption, S3–S4 | [TaskLedgerV2::install and same_skeleton](../../crates/savana-policy-core/src/v2/task_state.rs): history/counters remain; only identities/alternatives/dependencies determine skeleton; reservations keep their creation epoch | task_state_dependency_requires_signed_success_and_epoch_survives_aba; task_state_pending_old_outcome_and_retroactive_retry_cannot_expand_authority. Removed-clause tombstones, units and overflow have Rust tests but are outside the finite graph |
| Replay, S2–S3 | TaskLedgerV2::prepare replay branch checks original content, contract, policy, core, endorsements and settlement against immutable reservation. Durable preparation returns without new reservation commit | task_state_endorsements_settlement_nonce_and_original_replay_are_atomic. This is historical replay, not using old authority for a new execution identity |
| Fence / Emit, S2 and S6 | [OwnerBackedProviderAttemptV2::execute_and_retain](../../crates/savana-execd/src/worker_supervisor.rs): verify_equivalent, target/TLS and credential identity checks precede prepare_provider_attempt, record_effect_started and transport.execute | task_bound_worker_request_mutations_stop_before_prepare_or_provider_attempt; owner_backed_attempt_commits_effect_start_before_transport_and_response_afterward. Model collapses the two durable pre-send commits; no proof of codec equivalence or OS mediation |
| Retain / Certify, S5 | Same supervisor calls record_provider_response after transport; [complete_checked_business_result and retained_business_succeeded](../../crates/savana-execd/src/connector_runtime.rs) classify the retained response before completion | Native signed-worker mutation, provider failure and result-evidence tests. Correct signature alone is not success; the retained response and reviewed business classifier matter |
| Started / Settle, S3–S5 | [verify_task_outcome and reconcile_task_outcome](../../crates/savana-policy-core/src/v2/durable.rs) verify exact dispatch/authorization association. Reconciliation changes tasks, dispatch, quota and intent in one snapshot; TaskLedgerV2::reconcile uses the original refund rule | task_state_effect_started_unknown_and_raw_success_cannot_refund_or_unlock; no-effect refund test; terminal-first native fixture. The model omits concrete signature/hash/time validation |
| ACK, S7 | [Native completion path](../../crates/savana-kerneld/src/v2_agent_authority.rs) commits the vault result, reconciles the policy outcome, caches the local successful observation, then calls executor.acknowledge. [Execd ACK handler](../../crates/savana-execd/src/protocol_service.rs) checks query/completion binding | Native processed-ACK/lost-reply case. Execd does not read policy/vault storage; its nonzero kernel_commit_digest is not an independent proof of durability. Correct kernel-side ordering and authenticated caller identity are TCB obligations |
| Crash / Reopen, S3 and S6 | Policy durable commit poisons the owner after uncertain rename/anchor advancement; open validates adjacent durable state. [Execd durable mutate/commit/open](../../crates/savana-execd/src/durable.rs) preserves journal transitions. [recover_inner](../../crates/savana-execd/src/connector_runtime.rs) makes attempt-without-response indeterminate, or decodes a retained response without sending again | Actual encrypted-file reopen and uncertain-commit tests; native lost-dispatch-ACK/reopen case. No model proof of fsync/rename/hardware anchor or reconstruction of volatile native query handles |

## Durable commit cuts

The policy model's Reserve is **not** “sign a token and decrement a counter
later.” In the Rust implementation, none of the cloned state escapes until the
snapshot commit succeeds. A failure after atomic rename or during rollback-anchor
advancement poisons the owner and reports uncertainty. Reopen can adopt/validate
the adjacent committed snapshot; the caller cannot safely assume nothing happened.

The executor model's Fence compresses ProviderAttemptPrepared and EffectStarted.
Both are written before transport execution. Recovery from either without a
retained response becomes Indeterminate, even if the transport was never called.
This deliberately favors avoiding a new attempt over restoring availability.

Successful provider response retention, completion classification, policy
settlement and native result ownership are distinct boundaries in Rust.
The model separates the first three, but abstracts away the additional vault
commit. It must not be described as a three-owner model or proof of result-store
atomicity.

## Important negative findings from the source audit

1. Revocation is checked for new preparation. Already committed dispatches keep
   their historical binding; historical settlement and exact replay can remain
   valid. Do not promise instantaneous cancellation at the provider.
2. A nonzero commit digest in an authenticated ACK does not prove another owner
   has flushed its disk. S7 relies on trusted native caller ordering. The model's
   guard represents that ordering, not an extra verification performed by Execd.
3. Retained bytes do not imply known success. Response classification or checked
   worker decoding may fail after retention, resulting in Unknown.
4. A full kerneld restart still does not reconstruct every opaque client handle.
   The finite policy reopen transition concerns durable authority, not complete
   client-session availability.
5. The two-step native fixture uses predeclared A/Alice and B/Bob alternatives.
   Neither it nor the new model establishes authorization for runtime-discovered
   resources, unconstrained autonomous planning, or synthesized final answers.

These are claim boundaries, not newly introduced production changes.

## What a genuine refinement result would still require

- Define a concrete abstraction function from each Rust owner's stored records
  and in-flight messages to the specification history, including crash cuts.
- Prove or independently check every reachable concrete transition is a
  specification step or a permitted stutter, rather than only linking functions.
- Account for approval replay across tasks, registry/generation/expiry races,
  persistent tombstones, parser equivalence, arithmetic and storage failure.
- Include result ownership and native handle recovery, or explicitly exclude
  their availability from the theorem.
- Discharge or state crypto, codec, identity, provider and OS complete-mediation
  assumptions separately.

The current finite checker plus selected Rust tests is useful evidence toward
that result, not a substitute for it.
