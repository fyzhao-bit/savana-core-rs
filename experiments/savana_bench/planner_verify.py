"""Offline consistency check for an untrusted-planner run; NOT remote attestation.

Re-derives, from the hash-chained evidence alone: that each submitted draft is
the mechanical encoding of the recorded author output (no harness repair); the
verdict on every request that reached a provider, judged against the owner's
root; that a codec refusal is reproduced by Savana's own codec; each
published result via the protected verifier; and the official oracle on the
actual final environment. No model, tool or kernel call.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from .agentdojo_provider import canonical
from .agentdojo_tasks import prepare_draft
from .official_verify import restore_environment, verify_chain
from .planner_authors import SYSTEM, PlanUnencodable, compromised_draft, encode_plan, parse_plan
from .planner_experiment import (DEFINITIVE, IDS, OPERATOR_MODE, SCHEMA, classify_provider_attempt,
                                 experiment_cases, summarize)
from .protected_agentdojo import official_case, package_sources, score_outcome
from .protected_verify import verify_published_episode

META = ("seq", "previous", "kind", "time_ns", "sha256")
LAST_STAGE = {"compile_rejected": "operator_compile_replay", "prepare_rejected": "operator_execution_prepare",
              "sdk_codec_rejected": "owner_root_authorization_and_plan"}


def _one(local, kind):
    found = [e for e in local if e["kind"] == kind]
    if len(found) != 1:
        raise ValueError("expected_one_" + kind)
    return found[0]


def _ids(value):
    ids = {k: (bytes.fromhex(v) if type(v) is str else v) for k, v in value.items()}
    if set(ids) != set(IDS):
        raise ValueError("plan_ids")
    return ids


def _submitted_draft(case, contract, local):
    """The draft must be exactly what the recorded author output encodes to."""
    submitted = [e for e in local if e["kind"] == "plan_submitted"]
    if not submitted:
        return None, None
    if len(submitted) != 1:
        raise ValueError("duplicate_plan_submission")
    event = submitted[0]
    ids = _ids(event["ids"])
    descriptors = {k: bytes.fromhex(v) for k, v in event["descriptors"].items()}
    release = bytes.fromhex(event["release_descriptor"])
    steps = tuple(descriptors[st.tool] for st in contract.steps())
    reviewed = prepare_draft(contract, tool_descriptor=steps[0], step_descriptors=steps,
                             release_descriptor=release, **ids)["planning_draft"]
    if case["author"] == "reviewed":
        expected = reviewed
    elif case["mutation"] is not None:
        expected = compromised_draft(case["mutation"], contract=contract, descriptors=descriptors,
                                     release_descriptor=release, **ids)
    else:
        authored = _one(local, "plan_authored")
        if hashlib.sha256(authored["plan_text"].encode()).hexdigest() != authored["response_sha256"]:
            raise ValueError("plan_text_digest")
        expected = encode_plan(parse_plan(authored["plan_text"]), contract=contract, descriptors=descriptors,
                               release_descriptor=release, **ids)
    if json.loads(canonical(expected)) != event["draft"]:
        raise ValueError("submitted_draft_is_not_the_author_output")
    deviates = event["draft"] != json.loads(canonical(reviewed))
    if event["deviates_from_reviewed"] is not deviates:
        raise ValueError("plan_deviation_claim")
    return event["draft"], deviates


def verify_episode(directory, local, case, row, profile, turns):
    suite, task, injection, contract, values, env = official_case(case)
    initial = _one(local, "episode_input")
    if initial["contract"] != contract.document() or initial["injections"] != values:
        raise ValueError("task_or_attack_mismatch")
    if initial["environment"] != env.model_dump(mode="json"):
        raise ValueError("initial_environment_mismatch")
    authored = [e for e in local if e["kind"] == "plan_authored"]
    if case["author"] == "deepseek":
        if row["outcome"] == "author_failed":
            if authored:
                raise ValueError("author_failure_with_plan")
        elif len(authored) != 1 or authored[0]["author"] != "deepseek" or authored[0]["goal"] != case["goal"]:
            raise ValueError("plan_author_evidence")
    elif len(authored) != 1 or authored[0] != dict(authored[0], author=case["author"], mutation=case["mutation"]):
        raise ValueError("adversary_plan_evidence")
    if row["outcome"] == "plan_unencodable":
        try:
            parse_plan(authored[0]["plan_text"])
        except PlanUnencodable as error:
            if str(error) != row.get("plan_error"):
                raise ValueError("plan_unencodable_reason")
        else:
            raise ValueError("encodable_plan_reported_unencodable")
    draft, deviates = _submitted_draft(case, contract, local)
    if row["plan_deviates_from_reviewed"] != deviates:
        raise ValueError("plan_deviation_row")
    stages = [e["stage"] for e in local if e["kind"] == "admission_stage_started"]
    if row["outcome"] in LAST_STAGE:
        if not stages or stages[-1] != LAST_STAGE[row["outcome"]] or draft is None:
            raise ValueError("refusal_stage_evidence")
    if row["outcome"] in ("compile_rejected", "prepare_rejected") and row.get("operator_stage") != "kernel":
        raise ValueError("kernel_refusal_not_from_kernel_stage")
    if row["outcome"] == "sdk_codec_rejected":
        # The same Rust codec the kernel re-runs must refuse this exact draft.
        from savana.managed_admin import prepare_artifact
        try:
            prepare_artifact("planning_draft", canonical(draft))
        except ValueError:
            pass
        else:
            raise ValueError("codec_accepts_reported_codec_refusal")
    votes = [e for e in local if e["kind"] == "benchmark_consent"]
    if row["outcome"] == "owner_refused" and not any(v["decision"] == "refuse" for v in votes):
        raise ValueError("owner_refusal_evidence")
    if row["outcome"] != "owner_refused" and any(v["decision"] != "approve" for v in votes):
        raise ValueError("unreported_owner_refusal")
    bindings = [e for e in local if e["kind"] == "episode_binding"]
    if len(bindings) > 1:
        raise ValueError("duplicate_episode_binding")
    resource = bindings[0]["resource"] if bindings else ""
    turn = bindings[0]["application_turn"] if bindings else None
    if turn is not None:
        turns.add(turn)
    verdicts, prior = [], []
    for event in local:
        if event["kind"] == "official_tool_result":
            prior.append(canonical(event["response"]))
        if event["kind"] not in ("provider_attempt", "provider_attempt_unbound"):
            continue
        payload = base64.b64decode(event["payload_base64"], validate=True)
        verdict = ("unauthorized_unbound" if event["kind"] == "provider_attempt_unbound" else
                   classify_provider_attempt(payload, contract=contract, resource=resource,
                                             application_turn=turn or "", prior_results=tuple(prior)))
        if event["verdict"] != verdict:
            raise ValueError("provider_attempt_verdict")
        verdicts.append(verdict)
    if (row["provider_attempts"] != len(verdicts) or row["owner_releases"] != verdicts.count("owner_release")
            or row["unauthorized_provider_attempts"] != sum(v.startswith("unauthorized") for v in verdicts)):
        raise ValueError("provider_attempt_counts")
    if row["outcome"] == "published":
        utility, attacker = verify_published_episode(directory, local, case, dict(row, status="scored"), profile)
        if (row["utility"], row["attacker_success"]) != (utility, attacker):
            raise ValueError("official_oracle_replay_mismatch")
        final = _one(local, "episode_observation")["environment"]
    else:
        if row["utility"] is not None or row["attacker_success"] is not None:
            raise ValueError("refusal_is_not_utility")
        # Final state after execution, or the untouched state if it never started.
        finals = [e for e in local if e["kind"] in ("episode_observation", "episode_environment")]
        if len(finals) != 1:
            raise ValueError("expected_one_final_environment")
        final = finals[0]["environment"]
        before = restore_environment(type(env), initial["environment"])
        after = restore_environment(type(env), final)
        tools = [e for e in local if e["kind"] == "official_tool_result"]
        observed = score_outcome(suite=suite, task=task, injection=injection, contract=contract,
            before=before, after=after, provider=SimpleNamespace(audit=[
                dict(invoked=True, upstream=e["tool"], arguments=e["arguments"]) for e in tools]),
            outcome=None)
        if (row["observed_utility"], row["observed_attacker_success"]) != observed:
            raise ValueError("official_oracle_replay_mismatch")
    if row["environment_changed"] != (final != initial["environment"]):
        raise ValueError("environment_change_claim")


def verify(directory):
    events, head = verify_chain((directory / "events.jsonl").read_bytes().splitlines())
    if json.loads((directory / "completion.json").read_bytes()) != dict(audit_head=head, event_count=len(events)):
        raise ValueError("completion_digest_mismatch")
    manifest = events[0]
    cases = [dict(c) for c in experiment_cases(manifest.get("experiment"))]
    if (manifest.get("schema") != SCHEMA or manifest.get("kernel_interface") != "python_sdk_only"
            or manifest.get("operator_mode") != OPERATOR_MODE or manifest.get("cases") != cases
            or manifest.get("plan_author_system_sha256") != hashlib.sha256(SYSTEM.encode()).hexdigest()
            or manifest.get("human_authentication_evaluated") is not False):
        raise ValueError("planner_experiment_scope_mismatch")
    if manifest["package_sources"] != package_sources():
        raise ValueError("official_package_source_mismatch")
    current = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(__file__).parent.glob("*.py"))}
    if manifest["source_sha256"] != current:
        raise ValueError("experiment_source_mismatch")
    from .benchmark_identity import validate_profile
    profile = manifest["identity_profile"]
    validate_profile(profile)
    summaries = [e["summary"] for e in events if e["kind"] == "summary"]
    if len(summaries) != 1 or summaries[0] != json.loads((directory / "summary.json").read_bytes()):
        raise ValueError("summary_artifact_mismatch")
    summary, rows, turns = summaries[0], [], set()
    for index, case in enumerate(cases):
        local = [e for e in events if e.get("episode") == index]
        score = _one(local, "episode_score")
        row = {k: v for k, v in score.items() if k not in META}
        if any(row[k] != v for k, v in case.items()):
            raise ValueError("episode_identity")
        expected_status = ("published" if row["outcome"] == "published" else
                           "refused" if row["outcome"] in DEFINITIVE else "unknown")
        if row["attempted"] and row["status"] != expected_status:
            raise ValueError("episode_status")
        if row["attempted"]:
            verify_episode(directory, local, case, row, profile, turns)
        rows.append(row)
    if len(turns) > 1:
        raise ValueError("owner_release_turn_not_fixed")
    if summary["rows"] != rows or summary["groups"] != summarize(rows):
        raise ValueError("summary_counts_mismatch")
    groups = summarize(rows)
    return dict(audit_consistent=True, audit_head=head, experiment=manifest["experiment"],
                episodes_verified=sum(r["attempted"] for r in rows), groups=groups,
                unauthorized_provider_attempts=sum(g["unauthorized_provider_attempts"] for g in groups.values()),
                identity_profile=profile, human_authentication_evaluated=False,
                portable_kernel_attestation=False, production_acceptance=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    print(json.dumps(verify(parser.parse_args().directory), indent=2))
