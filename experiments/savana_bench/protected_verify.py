"""Offline audit consistency / official-oracle replay; NOT remote attestation.

No model requests, tools, kernel calls or reconstructed grants. A researcher
who can replace the entire evidence directory can also replace its hash chain;
retain completion.json independently. Native receipt metadata is not a portable
signature and cannot independently prove a deployment was honest.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from .agentdojo_provider import canonical
from .official_verify import rates, restore_environment, verify_chain
from .private_episode import PrivateOutcome
from .protected_agentdojo import CASES, official_case, package_sources, score_outcome


def publication_chain(path, expected_head):
    previous, events = "0" * 64, []
    for index, line in enumerate(path.read_bytes().splitlines()):
        value = json.loads(line)
        digest = value.pop("sha256")
        # PublicationAudit's canonical writer uses ensure_ascii=True.
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        if (value["schema"] != "savana-private-publication-observer-v1" or value["sequence"] != index
            or value["previous"] != previous or hashlib.sha256(encoded).hexdigest() != digest):
            raise ValueError("publication_audit_chain")
        previous = digest
        events.append(value["event"])
    if not events or previous != expected_head:
        raise ValueError("publication_audit_head")
    return events


def verify_published_episode(directory, local, case, row, profile, contract=None):
    """Offline checks for one published episode; returns the official (utility, attacker).
    A planner-drafted episode passes the contract its replayed owner review gave."""
    suite, task, injection, contract, values, env = official_case(case, contract)
    steps = contract.steps()
    if profile is not None:
        votes=[e for e in local if e['kind']=='benchmark_consent']
        policy='finite_calendar_preconsent_v1' if len(steps)==1 else 'finite_write_preconsent_v1'
        if ([v.get('purpose') for v in votes]!=['ingress','task_authorization',*['tool_execution']*len(steps),'final_release']
            or any(v.get('decision')!='approve' or v.get('human_review') is not False
                or v.get('policy')!=policy for v in votes)):
            raise ValueError('finite_consent_evidence_missing')
    if not row["attempted"] or row.get("model_calls", 0) < 1:
        raise ValueError("unattempted_episode_scored")
    initial = [e for e in local if e["kind"] == "episode_input"]
    final = [e for e in local if e["kind"] == "episode_observation"]
    tools = [e for e in local if e["kind"] == "official_tool_result"]
    received = [e for e in local if e["kind"] == "result_received"]
    if any(len(v) != 1 for v in (initial, final, received)) or len(tools) != len(steps):
        raise ValueError("missing_episode_evidence")
    initial, final, tool, received = initial[0], final[0], tools[-1], received[0]
    if initial["contract"] != contract.document() or initial["injections"] != values:
        raise ValueError("task_or_attack_mismatch")
    if initial["environment"] != env.model_dump(mode="json"):
        raise ValueError("initial_environment_mismatch")
    # Each official call, in order, is the reviewed operation with its derived
    # fields recomputed here from the earlier logged results at the signed path.
    from .agentdojo_calendar import SENTINELS
    from .agentdojo_tasks import expected_step_call
    prior = []
    for number, event in enumerate(tools):
        expected = expected_step_call(contract, number, prior)
        if (event["tool"] != steps[number].upstream_tool
                or event["arguments"] != {k: v for k, v in expected["arguments"].items() if k not in SENTINELS}):
            raise ValueError("official_function_trace_mismatch")
        prior.append(canonical(event["response"]))
    payload = base64.b64decode(final["output_base64"], validate=True)
    received_bytes = base64.urlsafe_b64decode(received["payload_base64"] + "="*(-len(received["payload_base64"]) % 4))
    if payload != received_bytes or payload != canonical(tool["response"]):
        raise ValueError("output_not_the_received_tool_result")
    if hashlib.sha256(payload).hexdigest() != received["payload_sha256"]:
        raise ValueError("received_payload_digest")
    chain = publication_chain(directory/f"publication-{row['episode']:02d}.jsonl", row["publication_audit_head"])
    if [e["kind"] for e in chain] != ["private_wait_started", "private_publication_committed",
            "private_payload_verified", "private_episode_observed"]:
        raise ValueError("publication_not_confirmed")
    metadata = {k: v for k, v in chain[1].items() if k != "kind"}
    if metadata != final["publication"] or chain[-1]["status"] != "published":
        raise ValueError("publication_metadata_mismatch")
    payload_digest = hashlib.sha256(b"SAVANA_FINAL_RELEASE_PAYLOAD_V2\0"
        + len(payload).to_bytes(8, "big") + payload).hexdigest()
    if metadata["payload_digest"] != payload_digest or chain[2]["payload_digest"] != payload_digest:
        raise ValueError("native_payload_commitment_mismatch")
    for key in ("task_id", "run_id", "root_digest", "destination_digest"):
        if chain[0][key] != metadata[key]:
            raise ValueError("publication_scope_rebound")
    if chain[2]["commit_digest"] != metadata["commit_digest"] or chain[2]["payload_bytes"] != len(payload):
        raise ValueError("verified_payload_rebound")
    before = restore_environment(type(env), initial["environment"])
    after = restore_environment(type(env), final["environment"])
    if after.model_dump(mode="json") != tool["environment"]:
        raise ValueError("unexplained_post_tool_environment_change")
    utility, attacker = score_outcome(suite=suite, task=task, injection=injection,
        contract=contract, before=before, after=after,
        provider=SimpleNamespace(audit=[dict(invoked=True, upstream=e["tool"], arguments=e["arguments"])
                                        for e in tools]),
        outcome=PrivateOutcome("published", "complete", 0, metadata, payload))
    return utility, attacker


def verify(directory):
    events, head = verify_chain((directory/"events.jsonl").read_bytes().splitlines())
    completion = json.loads((directory/"completion.json").read_bytes())
    if completion != dict(audit_head=head, event_count=len(events)):
        raise ValueError("completion_digest_mismatch")
    manifest = events[0]
    if (manifest.get("schema") != "savana-protected-agentdojo-v1"
        or manifest.get("kernel_interface") != "python_sdk_only"
        or manifest.get("cases") != list(CASES) or manifest.get("full_benchmark") is not False
        or manifest.get("adaptive_tool_output_model_loop") is not False):
        raise ValueError("protected_subset_scope_mismatch")
    if manifest["package_sources"] != package_sources():
        raise ValueError("official_package_source_mismatch")
    current = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(__file__).parent.glob("*.py"))}
    if manifest["source_sha256"] != current:
        raise ValueError("experiment_source_mismatch")
    summaries = [e["summary"] for e in events if e["kind"] == "summary"]
    if len(summaries) != 1 or summaries[0] != json.loads((directory/"summary.json").read_bytes()):
        raise ValueError("summary_artifact_mismatch")
    summary, rows = summaries[0], []
    profile=manifest.get('identity_profile')
    if profile is not None:
        from .benchmark_identity import validate_profile
        validate_profile(profile)
        if (manifest.get('consent_mode')!='finite_calendar_preconsent_v1'
            or manifest.get('human_authentication_evaluated') is not False):
            raise ValueError('benchmark_authentication_claim_mismatch')
    elif (manifest.get('consent_mode') not in (None,'interactive')
          or any(e['kind']=='benchmark_consent' for e in events)):
        raise ValueError('missing_benchmark_identity_profile')
    if any(summary.get(k)!=manifest.get(k) for k in ('identity_profile','consent_mode','human_authentication_evaluated')):
        raise ValueError('benchmark_identity_summary_mismatch')
    for index, case in enumerate(CASES):
        local = [e for e in events if e.get("episode") == index]
        scores = [e for e in local if e["kind"] == "episode_score"]
        if len(scores) != 1:
            raise ValueError("missing_or_duplicate_score")
        row = {k: v for k, v in scores[0].items() if k not in ("seq", "previous", "kind", "time_ns", "sha256")}
        if any(row[k] != value for k, value in case.items()) or row["status"] not in ("scored", "unknown"):
            raise ValueError("episode_identity_or_status")
        if row["status"] == "unknown":
            if row["utility"] is not None or row["attacker_success"] is not None:
                raise ValueError("unknown_is_not_safety")
        else:
            utility, attacker = verify_published_episode(directory, local, case, row, profile)
            if row["utility"] != utility or row["attacker_success"] != attacker:
                raise ValueError("official_oracle_replay_mismatch")
        rows.append(row)
    if (summary["rows"] != rows or summary["rates"] != rates(rows)
        or summary["protected_episodes_scored"] != sum(r["status"] == "scored" for r in rows)):
        raise ValueError("summary_counts_mismatch")
    return dict(audit_consistent=True, audit_head=head,
        identity_profile=profile,human_authentication_evaluated=False,
        official_episodes_rescored=sum(r["status"] == "scored" for r in rows),
        portable_kernel_attestation=False, production_acceptance=False, rates=rates(rows))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    print(json.dumps(verify(parser.parse_args().directory), indent=2))
