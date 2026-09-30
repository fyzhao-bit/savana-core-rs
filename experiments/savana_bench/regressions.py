"""Run existing Rust assertions, not a second Python security implementation.

These fixed synthetic COMPONENT tests are neither LLM trials nor production
hardware acceptance. A renamed/missing/ignored test cannot become a green zero.
"""
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
CASES = (
    ("savana-kernel-protocol", "private_publication_v04", "private_publication_canonical_unknown_and_exact_payload"),
    ("savana-kernel-protocol", "private_publication_v04", "private_publication_ipc_has_only_kernel_approval_role"),
    ("savana-kernel-protocol", "lib", "private_publication_http_is_owner_post_only"),
    ("savana-approvald", "lib", "private_publication_requires_live_owner_final_approval_and_exact_scope"),
    ("savana-client", "private_v04", "private_v04_publication_is_explicit_immutable_and_owner_only"),
    ("savana-client", "private_v04", "private_v04_publication_rebind_regression_and_corruption_close_capability"),
    ("savana-kernel-protocol", "final_release_business", "final_result_release_capsule_checks_actual_bytes_destination_and_evidence_against_core"),
    ("savana-kernel-protocol", "final_release_business", "final_result_codec_cannot_reuse_original_input_namespace_or_profile"),
    ("savana-kerneld", "lib", "fused_task_compiler_binds_separate_final_release_clause_before_execution"),
    ("savana-kerneld", "lib", "fused_final_release_native_pipeline_publishes_only_approved_terminal_result"),
    ("savana-kerneld", "lib", "fused_final_release_encrypted_reopen_reconciles_original_dispatch_without_session_or_resend"),
    ("savana-policy-core", "lib", "fused_task_compiler_final_source_is_explicit_signed_and_terminal"),
    ("savana-policy-core", "lib", "fused_final_source_profile_rejects_unsigned_changes_and_schema_downgrade"),
    ("savana-policy-core", "lib", "fused_final_result_requires_all_completions_and_original_checkpoint"),
    ("savana-policy-core", "lib", "fused_final_result_reopen_is_read_only_and_never_extends_authority"),
    ("savana-policy-core", "lib", "fused_final_result_requires_explicit_source_and_bounded_payload"),
    ("savana-policy-core", "lib", "fused_final_result_restore_rejects_erased_or_rebound_result"),
    ("savana-policy-core", "lib", "fused_final_result_failed_or_unknown_effect_never_becomes_completed_output"),
    ("savana-kerneld", "lib", "fused_final_result_native_pipeline_retains_terminal_bytes_without_publication"),
    ("savana-approvald", "lib", "kernel_release_delivery_is_task_bound_and_role_bound_across_restore"),
    ("savana-approvald", "lib", "private_release_handoff_is_separate_role_bound_and_cannot_replace_pending_tool"),
    ("savana-approvald", "lib", "approval_pair_reregistration_never_resets_signed_approval_or_denial"),
    ("savana-client", "private_v04", "private_v04_approval_and_denial_require_separate_ceremonies"),
    ("savana-policy-core", "lib", "fused_task_compiler_uses_signed_tools_and_inherits_root_dependencies"),
    ("savana-policy-core", "lib", "fused_task_compiler_rejects_authority_schema_and_dependency_changes"),
    ("savana-policy-core", "lib", "fused_task_compiler_accepts_only_signed_payload_result_edges"),
    ("savana-policy-core", "lib", "fused_task_compiler_draft_rejects_unknown_and_duplicate_fields"),
    ("savana-policy-core", "lib", "fused_task_compiler_signed_administration_is_atomic_replayable_and_requires_live_tools"),
    ("savana-continuation-core", "planning", "dynamic_observation_prefix_freeze_and_restoration"),
    ("savana-continuation-core", "planning", "dynamic_observation_unavailable_is_frozen_not_backfilled"),
    ("savana-continuation-core", "planning", "dynamic_observation_rejects_ambiguous_malformed_foreign_and_oversized_inputs"),
    ("savana-kerneld", "lib", "fused_dynamic_observation_from_real_execution_through_g3_survives_reopen"),
    ("savana-kerneld", "lib", "fused_dynamic_observation_without_g3_never_reaches_model_or_retries"),
    ("savana-kerneld", "lib", "fused_result_loop_passes_verified_predecessor_result_to_next_effect"),
    ("savana-kerneld", "lib", "fused_result_loop_three_steps_consume_immediate_predecessor_once"),
    ("savana-kerneld", "lib", "fused_result_loop_reopens_encrypted_owner_without_resending_predecessor"),
    ("savana-kerneld", "lib", "fused_result_loop_waits_for_exact_second_step_approval"),
    ("savana-kerneld", "lib", "fused_result_loop_revocation_stops_downstream_without_resetting_consumption"),
    ("savana-kerneld", "lib", "fused_result_loop_unknown_blocks_without_fabricating_result_or_refunding"),
    ("savana-continuation-core", "planning", "result_edges_require_schema_two_declared_predecessors_and_payload_slots"),
    ("savana-continuation-core", "planning", "model_cannot_supply_result_bindings_or_result_bytes"),
    ("savana-policy-core", "lib", "result_recipe_binds_profile_initial_inputs_and_exact_source_edge"),
    ("savana-policy-core", "lib", "result_utf8_derivation_preserves_untrusted_private_lineage_and_exact_bytes"),
    ("savana-policy-core", "lib", "result_utf8_derivation_rejects_bad_encoding_types_and_arity"),
    ("savana-kernel-protocol", "lib", "private_session_wire_is_canonical_bounded_and_role_separated"),
    ("savana-kernel-protocol", "lib", "private_session_http_does_not_accept_agent_origins_urls_or_get_mutations"),
    ("savana-kernel-protocol", "lib", "private_session_browser_authenticates_then_offers_only_separate_approval"),
    ("savana-approvald", "lib", "private_session_hardware_authentication_then_exact_kernel_handoff"),
    ("savana-approvald", "lib", "private_session_rejects_cross_task_expiry_and_boot_restart_handles"),
    ("savana-approvald", "lib", "private_session_rejects_legacy_purpose_and_wrong_principal"),
    ("savana-kerneld", "lib", "fused_private_session_consumes_exact_proof_without_agent_handles"),
    ("savana-kerneld", "lib", "fused_private_session_rejects_wrong_purpose_binding_principal_boot_key_and_expiry"),
    ("savana-continuation-core", "core", "raw_subject_or_error_difference_is_detected"),
    ("savana-continuation-core", "core", "actual_private_answers_are_independent_not_public_inputs"),
    ("savana-continuation-core", "core", "private_recovery_and_rejection_edges_are_not_skipped"),
    ("savana-continuation-core", "core", "resource_exhaustion_is_unknown_not_acceptance"),
    ("savana-continuation-core", "core", "fresh_execution_identity_cannot_renew_resource_consumption"),
    ("savana-continuation-core", "core", "snapshot_reopen_preserves_pin_and_freeze_without_current_facts"),
    ("savana-continuation-core", "core", "bounded_exhaustive_checker_and_independent_oracle_agree"),
    ("savana-continuation-core", "planning", "wire_has_no_private_root_scope_binding_or_execution_fields"),
    ("savana-continuation-core", "planning", "unsolicited_late_noncanonical_oversized_and_free_text_advice_rejected"),
    ("savana-continuation-core", "planning", "public_cut_fallback_cannot_be_changed_by_late_advice"),
    ("savana-continuation-core", "planning", "useful_replacement_preserves_started_execution_and_reorders_remaining_work"),
    ("savana-continuation-core", "planning", "individually_valid_plans_can_fail_cross_version_prefix_check"),
    ("savana-policy-core", "lib", "fused_outbox_reopen_returns_same_view_without_renewing_send_capacity"),
    ("savana-policy-core", "lib", "fused_uncertain_commit_never_returns_view_and_reopen_keeps_charged_attempt"),
    ("savana-policy-core", "lib", "fused_schedule_retries_follow_public_slots_not_model_success_or_failure"),
    ("savana-policy-core", "lib", "fused_schedule_slot_deadline_rejects_late_reply_without_early_retry"),
    ("savana-policy-core", "lib", "fused_g7_two_valid_plans_cannot_switch_across_an_already_started_prefix"),
    ("savana-policy-core", "lib", "fused_g7_late_old_outcomes_preserve_replacement_and_only_success_unblocks_dependencies"),
    ("savana-policy-core", "lib", "fused_recipe_g7_uncertain_commit_restores_receipt_and_consumption_once"),
    ("savana-policy-core", "lib", "fused_inputs_g7_checks_original_snapshot_even_with_signed_different_recipe"),
    ("savana-policy-core", "lib", "fused_execution_result_checkpoint_requires_success_and_is_immutable_after_reopen"),
    ("savana-policy-core", "lib", "complete_normal_abort_rollback_and_fail_safe_state_paths"),
    ("savana-policy-core", "lib", "successors_preserve_every_high_water_entry_and_key_epoch"),
    ("savana-policy-core", "lib", "intervening_chain_cannot_hide_skipped_ledger_or_enrollment_switch"),
    ("savana-policy-core", "lib", "history_requires_reviewed_genesis_exact_live_head_and_all_records"),
    ("savana-policy-core", "lib", "history_rejects_reused_transactions_and_consumed_rollback_grants"),
    ("savana-policy-core", "lib", "typed_evidence_matches_actual_installed_and_committed_ledger_chain"),
    ("savana-policy-core", "lib", "external_transaction_authorization_binds_every_v3_pre_state_field"),
    ("savana-policy-core", "lib", "v3_preparation_rejects_time_platform_pending_work_and_terminal_tag_only"),
    ("savana-policy-core", "v2_security_state_manifest", "complete_security_state_manifest_round_trips_and_rejects_signature_mutation"),
    ("savana-platform-identity", "lib", "archive_failure_never_advances_and_missing_ancestry_never_reopens"),
    ("savana-kerneld", "lib", "fused_private_loop_completes_two_dependent_clauses_without_repreparing_consumed_work"),
    ("savana-kerneld", "lib", "fused_private_loop_resumes_after_execution_memory_loss_without_resetting_consumption"),
    ("savana-kerneld", "lib", "fused_private_loop_rejects_planner_order_that_skips_signed_success_dependency"),
    ("savana-kerneld", "lib", "fused_private_loop_stops_when_root_is_revoked_between_steps"),
    ("savana-kerneld", "lib", "fused_private_loop_waits_for_new_action_approval_between_steps"),
    ("savana-kerneld", "lib", "fused_private_loop_completes_after_second_step_exact_approval_and_next_owner_tick"),
)


def test_command(package, target):
    base = ["cargo", "test", "--offline", "--locked", "-p", package]
    base += ["--lib"] if target == "lib" else ["--test", target]
    # Enables only the synthetic provider/fixture keys; production startup and
    # native identity acceptance must never be inferred from these cases.
    if package == "savana-kerneld":
        base += ["--features", "test-support"]
    return base


def command(argv, timeout):
    """Never shell-evaluate inputs; kill only our child process group on timeout."""
    with tempfile.TemporaryFile() as output:
        try:
            proc = subprocess.Popen(argv, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT,
                                    start_new_session=True, env={**os.environ, "CARGO_TERM_COLOR": "never"})
        except OSError:
            return "error", ""
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
            return "timeout", ""
        if output.tell() > 8 * 1024 * 1024:
            return "error", ""
        output.seek(0)
        return ("ok" if proc.returncode == 0 else "error"), output.read().decode("utf-8", "replace")


def selected_name(listing, short_name):
    names = [line[:-6] for line in listing.splitlines() if line.endswith(": test")]
    matches = [n for n in names if n.split("::")[-1] == short_name]
    if len(matches) != 1:
        raise ValueError("test_missing_or_ambiguous")
    return matches[0]


def exactly_one_passed(status, output):
    return status == "ok" and bool(re.search(
        r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out;", output
    ))


def run(timeout=600, emit=None):
    rows = []
    listings = {}
    for package, target, test in CASES:
        started = time.monotonic()
        base = test_command(package, target)
        key = package, target
        if key not in listings:
            listings[key] = command(base + ["--", "--list"], timeout)
        state, listing = listings[key]
        if state == "ok":
            try:
                name = selected_name(listing, test)
                state, output = command(base + [name, "--", "--exact"], timeout)
                if not exactly_one_passed(state, output):
                    state = "timeout" if state == "timeout" else "error"
            except ValueError:
                state = "error"
        row = {"package": package, "test": test, "status": "passed" if state == "ok" else state,
               "seconds": round(time.monotonic() - started, 3)}
        rows.append(row)
        if emit:
            emit(row)
    return {"schema": "savana-component-regressions-v1", "scope": "component_only",
            "model_trials": 0, "production_acceptance": False, "tests": rows,
            "passed": sum(r["status"] == "passed" for r in rows), "total": len(rows)}
