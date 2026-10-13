"""Offline replay of one published episode and its official oracle; NOT remote attestation.

Used by the untrusted-planner verifier (`planner_verify`). No model requests,
tools, kernel calls or reconstructed grants. A researcher who can replace the
entire evidence directory can also replace its hash chain; retain
completion.json independently. Native receipt metadata is not a portable
signature and cannot independently prove a deployment was honest.
"""
import base64
import hashlib
import json
import re
from types import SimpleNamespace

from .agentdojo_provider import canonical, decode
from .official_verify import restore_environment
from .private_episode import PrivateOutcome
from .protected_agentdojo import official_case, score_outcome


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


def verify_published_episode(directory, local, case, row, profile, contract, continued=None):
    """Offline checks for one published episode; returns the official (utility, attacker).
    `contract` is the planner-drafted contract its replayed owner review gave.
    An act turn (`adopted_instructions`) passes `continued`: the environment it
    started from (its read turn's final one), the environment the task started
    from, and the read turn's official calls, which head the scored trace."""
    suite, task, injection, contract, values, env = official_case(case, contract)
    steps = contract.steps()
    if profile is not None:
        votes=[e for e in local if e['kind']=='benchmark_consent']
        base='finite_calendar_preconsent_v1' if len(steps)==1 else 'finite_write_preconsent_v1'
        policy=votes[0].get('policy') if votes else None
        owner={'strict':'+strict_destination','directory':'+directory_destination','set':'+candidate_destination'}.get(case.get('owner'),'')
        if policy not in (base+m+owner for m in ('','+permit')):
            raise ValueError('finite_consent_evidence_missing')
        if '+permit' in policy:
            # Under a permit disposition only escalated steps ask, each once,
            # in ascending clause order.
            asked=[v.get('clause') for v in votes if v.get('purpose')=='tool_execution']
            ordered=(all(type(c) is int and 1<=c<=len(steps) for c in asked)
                     and asked==sorted(set(asked)))
        else:
            asked=[None]*len(steps);ordered=True
        if ([v.get('purpose') for v in votes]!=['ingress','task_authorization',*['tool_execution']*len(asked),
                                                 'final_release']
            or not ordered
            or any(v.get('decision')!='approve' or v.get('human_review') is not False
                or v.get('policy')!=policy for v in votes)):
            raise ValueError('finite_consent_evidence_missing')
    if not row["attempted"] or row.get("model_calls", 0) < 1:
        raise ValueError("unattempted_episode_scored")
    initial = [e for e in local if e["kind"] == "episode_input"]
    final = [e for e in local if e["kind"] == "episode_observation"]
    tools = [e for e in local if e["kind"] in ("official_tool_result", "executor_local_result")]
    received = [e for e in local if e["kind"] == "result_received"]
    if (any(len(v) != 1 for v in (initial, final, received)) or len(tools) != len(steps)
            or [e["operation"] for e in tools] != list(range(1, len(steps) + 1))):
        raise ValueError("missing_episode_evidence")
    initial, final, tool, received = initial[0], final[0], tools[-1], received[0]
    if initial["contract"] != contract.document() or initial["injections"] != values:
        raise ValueError("task_or_attack_mismatch")
    if initial["environment"] != (env.model_dump(mode="json") if continued is None else continued["environment"]):
        raise ValueError("initial_environment_mismatch")
    # Each operation, in order: one the kernel's executor answers itself is
    # recomputed here and never reached the provider; every other is the
    # reviewed call with its derived fields recomputed here from the earlier
    # logged results at the signed path, as it reached the provider.
    from .agentdojo_provider import response as mcp_response
    from .agentdojo_tasks import LOCAL_REQUEST_ID, executor_local_text, expected_wire_params
    from .dojo_catalog import CATALOG, SENTINELS, official_call
    from .value_blind import EXTRACTOR_CODECS
    model_codec = EXTRACTOR_CODECS[case.get("extractor_view", "raw")]
    prior = []
    for number, event in enumerate(tools):
        local_text = executor_local_text(contract, number, prior)
        if event["kind"] == "executor_local_result":
            if (local_text is None or event["tool"] != steps[number].tool
                    or event["response"] != decode(mcp_response(LOCAL_REQUEST_ID, "succeeded", local_text))):
                raise ValueError("executor_local_result_mismatch")
        else:
            if local_text is not None:
                raise ValueError("local_operation_reached_provider")
            expected, _masker = expected_wire_params(contract, number, prior, model_codec)
            if any(t["operation"] == steps[number].tool for t in CATALOG):
                _, official = official_call(steps[number].tool, expected["arguments"])
            else:
                official = {k: v for k, v in expected["arguments"].items() if k not in SENTINELS}
            if event["tool"] != steps[number].upstream_tool or event["arguments"] != official:
                raise ValueError("official_function_trace_mismatch")
        prior.append(canonical(event["response"]))
    payload = base64.b64decode(final["output_base64"], validate=True)
    received_bytes = base64.urlsafe_b64decode(received["payload_base64"] + "="*(-len(received["payload_base64"]) % 4))
    released = tool["response"]
    if tool["kind"] == "executor_local_result":
        # A local answer's envelope echoes the kernel's own request id.
        echoed = decode(payload).get("id") if payload.startswith(b"{") else None
        if type(echoed) is not str or not re.fullmatch(r"step-[0-9a-f]{64}", echoed):
            raise ValueError("output_not_the_received_tool_result")
        released = dict(released, id=echoed)
    if payload != received_bytes or payload != canonical(released):
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
    before = restore_environment(type(env), initial["environment"] if continued is None else continued["before"])
    after = restore_environment(type(env), final["environment"])
    if after.model_dump(mode="json") != tool["environment"]:
        raise ValueError("unexplained_post_tool_environment_change")
    utility, attacker = score_outcome(suite=suite, task=task, injection=injection,
        contract=contract, before=before, after=after,
        provider=SimpleNamespace(audit=[*([] if continued is None else continued["trace"]),
                                        *(dict(invoked=True, upstream=e["tool"], arguments=e["arguments"])
                                          for e in tools)]),
        outcome=PrivateOutcome("published", "complete", 0, metadata, payload))
    return utility, attacker
