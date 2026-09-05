# Implementation-to-claim map

Research snapshot: 2026-09-05, branch `codex/intent-bound-execution`.
Read together with [verification evidence](intent-bound-execution.md). A test name
is an executable witness, not a theorem or a measured population result.

| Paper mechanism | Production authority/path | Executable evidence | Claim boundary |
| --- | --- | --- | --- |
| Authenticated task root before planning | `savana-kerneld/src/v2_task_authority.rs`, `v2_input_owner.rs`; policy `task_issuance.rs` | Native issuer/context tests; pending issuance uncertain-commit and wrong identity tests | Bounded structured input or independently approved draft; no general natural-language compiler |
| Complete joint action relation | policy `task_authorization.rs` | `task_authorization_tests.rs`: cross-pair, summary-only, stale generation, approval mutation | Exact contract relation; broad authorized contracts can still allow unwanted choices |
| Complete candidate domain | policy `task_authorization.rs`, `control_selection.rs` | Singleton and partial-domain refusal tests | Only complete bounded contract alternatives; not search-result completeness |
| Separate control evidence | policy `control_selection.rs`, ordinary `provenance.rs` | Seven-plane mutation and READ-ceiling checks | Endorsement does not relabel a data node or become a general derivation parent |
| Acyclic content/authorization commitments | protocol `task_authorization.rs`, policy `control_selection.rs`, `binding.rs` | Independent literal digest vectors; endorsement/settlement substitution tests | Content excludes future approvals; authorization includes exact endorsement set/state transition |
| Task-wide atomic consumption | policy `task_state.rs`, `durable.rs` | `task_state_concurrent_prepares_and_file_lock_have_one_winner`; uncertain commit; new-run/overflow/revocation tests | Attempt/magnitude accounting, not exactly-once remote effects |
| Exact readable approval | protocol `task_action_display.rs`, approvald `protocol_service.rs`, native `v2_agent_authority.rs` | Real approvald ceremony/recovery; wrong action/task/settlement refusal; display escaping/oversize tests | Correct rendering does not prove human understanding or freedom from phishing |
| Exact registered connector | policy `connector_registry.rs`; execd `protocol_service.rs` | `strict_task_route_rechecks_profile_activity_and_signed_removal`; native missing/rename/duplicate cases | Descriptor provider identity must pin connector identity; active signed profile required |
| Actual request mediation | protocol `business_request.rs`; execd `worker_supervisor.rs`, `provider_transport.rs` | `task_bound_worker_request_mutations_stop_before_prepare_or_provider_attempt`; native malicious signed worker case | Closed application request and transport target, not arbitrary provider-internal semantics or TLS-byte equivalence |
| Authoritative known outcome | execd `connector_runtime.rs`; protocol `task_completion.rs`; native completion verification | Failure/unknown/wrong-ID retained response tests; signed terminal verification; two-step native fixture | Known success according to reviewed response codec; trusted provider semantics remain an assumption |
| Multiple immutable task results | vault `lib.rs`, `durable.rs`; native `v2_data_plane.rs` | `durable_tool_results_are_distinct_replayable_and_cannot_replace_original_input`; native two-step result commits | Internal verified-result insertion, not a new agent-controlled ingress route |
| Dispatch/ACK uncertainty | native `v2_agent_authority.rs`, executor encrypted journal | Nine-case tool and seven-case release native fixtures | Same native owner retains handles; executor restart tested; full kerneld restart does not restore opaque query handles |
| Receiver-bound final release | protocol `final_release_business.rs`; openclaw-release `reservation.rs`, `server.rs` | Native final release; mTLS receiver wrong-turn/legacy-body tests | Original owned document, at most 32 KiB; no arbitrary synthesized output producer |
| SDK and planning order | `savana-client/src/task_authorization.rs`; Python bridge runtime; OpenClaw integration | Python 61 tests; TypeScript 65 tests; browser DOM output decoded by Rust | Host task.draft broker/live hardware deployment not demonstrated |
| Bounded state exploration | test-only policy `task_authorization_model.rs` | 1,440 differential traces, 984 admitted/1,896 refused probes, six accounting observations | Bounded accounting abstraction; no exhaustive distributed model or machine-checked proof |

## Claims deliberately not made

The revised paper maps this table to Sections 3–7 (implemented mechanisms),
Section 8 (conditional abstract argument), Section 9 (engineering evidence),
Section 10 (unrun experiments) and Section 12 (limitations). It uses code snapshot
73e0684; the paper build and visual checks are recorded in the verification file.

- No new claim to invent capabilities, endorsement, IFC, deterministic agent
  monitors, task-scoped authority, or temporal policies. Comparisons must include
  CaMeL, Fides, Progent, PCAS/FORGE, IGAC, CapAgent and classical endorsement.
- No semantic declassification/noninterference theorem for arbitrary natural
  language; leak scanning and reader-set enforcement are different properties.
- No claim that context isolation prevents a malicious planner from choosing
  between alternatives the user actually authorized.
- No full-kernel restart availability, universal exactly-once execution, complete
  hardware deployment, all-browser interoperability, or production readiness.
- No fabricated vulnerability: the existing plan-template/committed-plan checks
  were already present; this work must not claim to have newly added a missing
  whitelist. Actual integrated regressions found here concern connector routing,
  schema-specific subject hashes, result digest domains, terminal-first intent
  reconciliation, multi-result vault identities and lost acknowledgements.
- No security/utility/performance percentages from unit or fixture counts. The
  paper must label engineering evidence separately from unmeasured experiments.
