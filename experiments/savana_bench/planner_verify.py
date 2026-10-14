"""Offline consistency check for an untrusted-planner run; NOT remote attestation.

Re-derives, from the hash-chained evidence alone: the owner's review of every
recorded draft, and that each submitted draft is exactly the reviewed draft of
the admitted program (no harness repair); the verdict on every request that
reached a provider, judged against the owner's root; that a codec refusal is
reproduced by Savana's own codec; each published result via the protected
verifier; and the official oracle on the actual final environment. No model,
tool or kernel call.
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
from .planner_experiment import (DEFINITIVE, IDS, OPERATOR_MODE, SCHEMA, STRUCTURED_REFUSALS,
                                 classify_provider_attempt, directory_provenance, experiment_cases, planner_directory,
                                 planner_exposure, destination_candidates, structured_provenance, summarize,
                                 turn_request)
from .protected_agentdojo import official_case, package_sources, score_outcome
from .protected_verify import official_trace, verify_published_episode

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


def _submitted_draft(contract, local):
    """The draft must be exactly the reviewed draft of the admitted program,
    for the IDs and descriptors the kernel actually supplied."""
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
    if json.loads(canonical(reviewed)) != event["draft"]:
        raise ValueError("submitted_draft_is_not_the_author_output")
    if event["deviates_from_reviewed"] is not False:
        raise ValueError("plan_deviation_claim")
    return event["draft"], False


def _adopted_report(case, prior):
    """The read turn's report if the owner adopted it, else None, recomputed
    from the read episode's own evidence: its released payload and the owner's
    directory (`adopted_instructions`). The recorded decision must match."""
    from .adopted_instructions import adoption_record, report_text
    from .owner_directory import owner_directory
    decisions = [e for e in prior if e["kind"] == "instructions_adoption"]
    if len(decisions) != 1:
        raise ValueError("instructions_adoption_evidence")
    recorded = {k: decisions[0].get(k) for k in ("adopted", "reason", "text_sha256", "addresses")}
    if _one(prior, "episode_score")["outcome"] != "published":
        if recorded != dict(adopted=False, reason="read_turn_not_published", text_sha256=None, addresses=None):
            raise ValueError("instructions_adoption_mismatch")
        return None
    report = report_text(base64.b64decode(_one(prior, "episode_observation")["output_base64"], validate=True))
    if recorded != adoption_record(report, owner_directory(case["suite"])):
        raise ValueError("instructions_adoption_mismatch")
    return report if recorded["adopted"] else None


def _final_environment(local):
    finals = [e for e in local if e["kind"] in ("episode_observation", "episode_environment")]
    if len(finals) != 1:
        raise ValueError("expected_one_final_environment")
    return finals[0]["environment"]


def _drafted_contract(case, local, row, prior=None):
    """Replay the owner's fixed review of every recorded draft, in order: each
    draft before the last must be refused with exactly the recorded code and
    location, and the last must yield the recorded contract or refusal. The
    digest of what the planner was actually sent is recomputed from the
    request, the catalog and the earlier refusals alone, so the planner
    provably saw nothing else (no tool result, no model output). Under a
    masked view the planner also provably saw none of the owner's values: the
    masked request is recomputed with the kernel's leak-gate definition, and
    no owner-supplied message (system, request, refusal feedback) may contain
    a value the mask hid. A turn of instructions found in data drafts from its
    turn's request (`turn_request`); an act turn's is recomputed from its read
    turn's evidence (`prior`), and an act turn whose report was not adopted
    drafted nothing."""
    from agentdojo.task_suite.load_suites import get_suite
    from .agentdojo_tasks import BENCHMARK, register_drafted
    from .drafted_tasks import ProgramRefused, parse_program_text, performs_action, requested_action, review_program
    from .root_drafter import NON_RETRYABLE, draft_request_body
    from .value_blind import planner_request
    drafted = [e for e in local if e["kind"] == "root_drafted"]
    refusals = [e for e in local if e["kind"] == "program_refused"]
    max_drafts = case["max_drafts"]
    official = get_suite(BENCHMARK, case["suite"])
    prompt = official.get_user_task_by_id(case["user"]).PROMPT
    turn = case.get("instructions")
    request = turn_request(case, prompt, _adopted_report(case, prior) if turn == "act" else None)
    if request is None:
        if drafted or refusals or row["outcome"] != "instructions_not_adopted" or "drafts" in row:
            raise ValueError("unadopted_instructions_were_drafted")
        return None
    if [e.get("attempt") for e in drafted] != list(range(1, len(drafted) + 1)) or len(drafted) > max_drafts:
        raise ValueError("root_drafter_evidence")
    if row.get("drafts") != len(drafted):
        raise ValueError("draft_count_row")
    tools = {t.name for t in official.tools}
    view = case.get("planner_view", "request")
    _request, bindings = planner_request(prompt, view)
    history, contract, refusal, asked = [], None, None, False
    exposure = planner_exposure(case)
    for number, event in enumerate(drafted, 1):
        if case.get("root_author") == "fixed":
            # No planner: the program is the fixed text for this task.
            from .fixed_programs import fixed_program_text
            if (event.get("request_sha256") is not None
                    or event["program_text"] != fixed_program_text(case["suite"], case["user"])):
                raise ValueError("fixed_program_evidence")
        elif case.get("root_author") == "registered" or case.get("mapper") == "template":
            # No planner: the program is this task's registered template.
            from .structured_templates import load_registry, program_text
            if (event.get("request_sha256") is not None
                    or event["program_text"] != program_text(load_registry(), case["suite"], case["user"])):
                raise ValueError("registered_program_evidence")
        else:
            body = draft_request_body(official, request, model=case["planner_model"], goal=case.get("goal"),
                                      history=tuple(history), view=view, exposure=exposure,
                                      directory=planner_directory(case), compute=case.get("compute", "table"))
            if hashlib.sha256(body).hexdigest() != event["request_sha256"]:
                raise ValueError("planner_input_mismatch")
            if event.get("view", "request") != view or event.get("placeholders", 0) != len(bindings):
                raise ValueError("planner_view_evidence")
            owner_sent = [m["content"] for m in json.loads(body)["messages"] if m["role"] != "assistant"]
            if any(value in text for _placeholder, value in bindings for text in owner_sent):
                raise ValueError("planner_saw_owner_value")
        if hashlib.sha256(event["program_text"].encode()).hexdigest() != event["response_sha256"]:
            raise ValueError("program_text_digest")
        try:
            contract = review_program(suite=case["suite"], suite_tools=tools, task_id=case["user"],
                                      prompt=request, program=parse_program_text(event["program_text"]),
                                      bindings=bindings,
                                      extractor_model=case.get("extractor_model", "deepseek-flash"),
                                      derived_destinations=case.get("review") == "derived",
                                      read_only=turn == "read", destination_candidates=destination_candidates(case),
                                      calc=case.get("compute") == "calc", final_answer=case.get("answer") == "final")
            refusal = None
        except ProgramRefused as error:
            contract, refusal = None, error
            history.append((event["program_text"], str(error), error.step, error.field))
        if (contract is not None and case.get("actions") == "ask" and not asked and number < max_drafts
                and turn != "read" and requested_action(request) and not performs_action(contract)):
            # The runner asked once whether the request's action was left out
            # on purpose: nothing was signed, and the planner drafted again.
            asked, contract = True, None
            history.append((event["program_text"], "omitted_write", None, None))
        if contract is not None and number != len(drafted):
            raise ValueError("accepted_program_was_redrafted")
        if refusal is not None and str(refusal) in NON_RETRYABLE and number != len(drafted):
            raise ValueError("policy_refusal_was_redrafted")
    expected = [dict(attempt=i, reason=reason, step=step, field=field)
                for i, (_text, reason, step, field) in enumerate(history, 1)]
    if [{k: e.get(k) for k in ("attempt", "reason", "step", "field")} for e in refusals] != expected:
        raise ValueError("program_refusal_mismatch")
    if row["outcome"] == "author_failed":
        # The drafter failed on the attempt after the last recorded draft.
        if (contract is not None or len(drafted) >= max_drafts
                or (refusal is not None and str(refusal) in NON_RETRYABLE)):
            raise ValueError("drafter_failure_with_program")
        _service_unanswered(case, local)
        return None
    if refusal is not None:
        # Drafting ends at the limit, or early on a final policy refusal.
        if (row["outcome"] != "program_refused" or row.get("refusal") != str(refusal)
                or (len(drafted) != max_drafts and str(refusal) not in NON_RETRYABLE)):
            raise ValueError("program_refusal_mismatch")
        _service_unanswered(case, local)
        return None
    if contract is None and not drafted and case.get("mapper") == "service" and row["outcome"] == "mapper_failed":
        # agentd failed the job before its mapper request: nothing was drafted.
        _service_unanswered(case, local)
        return None
    if contract is None:
        raise ValueError("root_drafter_evidence")
    if row["outcome"] == "program_refused":
        raise ValueError("program_refusal_mismatch")
    if case.get("root_author") == "structured":
        return _structured_contract(case, local, row, register_drafted(contract), prompt=request,
                                    read_only=turn == "read")
    if row["outcome"] in STRUCTURED_REFUSALS:
        raise ValueError("structured_outcome")
    return register_drafted(contract)


def _service_unanswered(case, local):
    """For a service mapper that produced no program: agentd's job was the one
    its recorded salt fixes, and agentd got no workflow, so no planner was
    asked. Any other mapper has nothing to check here."""
    if case.get("mapper") != "service":
        return
    from .structured_planning import DRAFTED_INTENT, DRAFTED_TEMPLATE, ServiceMapper, eval_catalog, job_limits
    event = _one(local, "structured_planned")
    request = ServiceMapper(eval_catalog(case["suite"]), None, salt=bytes.fromhex(event["salt"]),
                            limits=job_limits(case.get("answer") == "final")).request_bytes
    if (event["outcome"] != "mapper_failed" or event["status"] == "accepted"
            or hashlib.sha256(request).hexdigest() != event["mapper_request_sha256"]
            or (event["intent"], event["template"]) != (DRAFTED_INTENT, DRAFTED_TEMPLATE)
            or any(event[key] is not None for key in ("mapper_response", "planner_request", "planner_response", "plan"))
            or event["planner_calls"]):
        raise ValueError("structured_service_evidence")


def _structured_contract(case, local, row, contract, *, prompt, read_only=False):
    """agentd's structured planning of the accepted program, re-derived from
    the evidence: the conversion (the mapper request's digest and the exact
    workflow agentd took) from the reviewed program, the recorded salt and
    the catalog; the planner request decoded and found to be exactly that
    workflow anonymised under the order agentd decoded, the planner model's
    prompt the pure function of it (its digest) and its reply the recorded
    order; no owner literal, leak-gate value, tool name or description in any
    planner byte; and the lowering and the owner's review of the lowered
    program. `prompt` is the turn's request the draft was reviewed against
    (`turn_request`: for an act turn, recomputed from its read turn's
    evidence); the scan for owner values and the review of the lowered
    program use it too, as the draft's review did (read-only for a read turn,
    with the set owner's candidates).
    Returns the lowered contract, or None for a recorded refusal (nothing
    signed)."""
    from .agentdojo_tasks import register_drafted
    from .drafted_tasks import ProgramRefused
    from .structured_planning import (EVIDENCE, OP, PLANNER_CODES, ProgramMapper, ServiceMapper, StructuredError,
                                      eval_catalog, exposure, job_limits, lower_plan, order_reply, planner_body,
                                      planner_view, review, sentinels)
    from .structured_templates import load_registry, template_number
    from .structured_wire import (WireError, decode_order, decode_ordered_plan, decode_plan, decode_structural_request,
                                  validate_order)
    event = _one(local, "structured_planned")
    outcome = event["outcome"]
    if (outcome not in ("planned", *STRUCTURED_REFUSALS)
            or (row["outcome"] in STRUCTURED_REFUSALS) != (outcome != "planned")
            or (outcome != "planned" and row["outcome"] != outcome)):
        raise ValueError("structured_outcome")
    catalog = eval_catalog(case["suite"])
    program = json.loads(contract.program)
    template = case["mapper"] == "template"
    limits = job_limits(case.get("answer") == "final")
    if case["mapper"] == "service":
        # The job was fixed before the program existed; the workflow is the
        # accepted program on that job's slots.
        try:
            mapper = ServiceMapper.replay(catalog, program, salt=bytes.fromhex(event["salt"]), limits=limits)
        except (StructuredError, ValueError):
            # The accepted program did not fit the job: agentd got no workflow.
            _service_unanswered(case, local)
            if row["outcome"] != "mapper_failed":
                raise ValueError("structured_service_evidence") from None
            return None
    else:
        try:
            mapper = ProgramMapper(program, catalog, source="template" if template else "drafted",
                                   template=(template_number(load_registry(), case["suite"], case["user"])
                                             if template else None),
                                   salt=bytes.fromhex(event["salt"]), limits=limits)
        except (StructuredError, WireError) as error:
            # The fixed conversion refused the accepted program: agentd got no
            # job, and the record says exactly that and nothing more.
            if (outcome != "mapper_failed" or event["error"] != str(error) or event["planner_calls"]
                    or any(event[key] is not None for key in EVIDENCE
                           if key not in ("job", "outcome", "error", "salt"))):
                raise ValueError("structured_mapper_evidence") from None
            return None
    if (hashlib.sha256(mapper.request_bytes).hexdigest() != event["mapper_request_sha256"]
            or (event["intent"], event["template"]) != (mapper.intent, mapper.template)
            or event["mapper_response"] not in (None, mapper.response.hex())):
        raise ValueError("structured_mapper_evidence")
    reached = outcome != "mapper_failed"
    accepted = outcome in ("planned", "lowering_failed")
    if (reached != (event["planner_request"] is not None) or (reached and event["mapper_response"] is None)
            or accepted != (event["status"] == "accepted") or accepted != (event["plan"] is not None)
            or (outcome == "planner_invalid") != (event["error"] in PLANNER_CODES)):
        raise ValueError("structured_stage_evidence")
    calls = event["planner_calls"]
    if not reached:
        if calls:
            raise ValueError("structured_stage_evidence")
        return None
    planner_bytes = bytes.fromhex(event["planner_request"])
    request = decode_structural_request(planner_bytes)
    labels, view = planner_view(request)
    if exposure((planner_bytes, view.encode()), sentinels(program, prompt, catalog)):
        raise ValueError("structured_planner_exposure")
    if len(calls) > 1 or any(call["request_sha256"] != hashlib.sha256(planner_bytes).hexdigest()
                             or call["prompt_sha256"] != hashlib.sha256(
                                 planner_body(request, model=case["planner_model"])[1]).hexdigest() for call in calls):
        raise ValueError("structured_planner_input")
    content = calls[0]["content"] if calls else None
    if outcome == "planner_invalid":
        # The recorded model reply decides which refusal agentd could give:
        # unencodable -> no reply sent; not a forward permutation -> agentd
        # refuses it; a valid order -> only a lost or late reply.
        if content is not None:
            try:
                encoded = order_reply(content, labels)
            except StructuredError:
                encoded = None
            valid = False
            if encoded is not None:
                try:
                    valid = bool(validate_order(request, decode_ordered_plan(encoded)))
                except ValueError:
                    valid = False
            expected = (("planner_unavailable",) if encoded is None else
                        ("planner_deadline", "planner_unavailable") if valid else ("planner_invalid_plan",))
            if event["error"] not in expected:
                raise ValueError("structured_planner_refusal")
        return None
    reply = bytes.fromhex(event["planner_response"])
    ordered = validate_order(request, decode_ordered_plan(reply))
    if not calls or order_reply(content, labels) != reply:
        raise ValueError("structured_planner_reply")
    plan = decode_plan(bytes.fromhex(event["plan"]))
    workflow = mapper.conversion.workflow
    positions = {node: mapper.conversion.ops.get(dict(step.bindings).get(OP)) for node, step in zip(ordered, plan.steps)}
    ids = {ordinal: node for node, ordinal in positions.items()}
    if sorted(ids) != [n.ordinal for n in workflow.nodes]:
        raise ValueError("structured_plan")
    # What the planner was sent is exactly this workflow, anonymised.
    graph = {n.id: (n.role, n.effects, n.in_arity, n.out_arity) for n in request.nodes}
    if (graph != {ids[n.ordinal]: (n.role, n.effects, sum(b == n.ordinal for _a, b in workflow.edges),
                                   sum(a == n.ordinal for a, _b in workflow.edges)) for n in workflow.nodes}
            or set(request.edges) != {(ids[a], ids[b]) for a, b in workflow.edges}):
        raise ValueError("structured_planner_graph")
    if decode_order(workflow.nodes, workflow.edges, ordered, positions) != plan.steps:
        raise ValueError("structured_plan")
    order = [positions[node] for node in ordered]
    if event["order"] != order or event["order_changed"] != (order != sorted(order)):
        raise ValueError("structured_plan")
    try:
        lowered = lower_plan(mapper.conversion, plan.steps)
    except StructuredError as error:
        if outcome != "lowering_failed" or event["lowering_error"] != str(error):
            raise ValueError("structured_lowering") from None
        return None
    if event["lowered"] != lowered:
        raise ValueError("structured_lowering")
    try:
        reviewed = review(lowered, suite=case["suite"], user=case["user"], extractor_model=case["extractor_model"],
                          derived_destinations=case.get("review") == "derived", calc=case.get("compute") == "calc",
                          final_answer=case.get("answer") == "final", prompt=prompt, read_only=read_only,
                          destination_candidates=destination_candidates(case))
    except ProgramRefused as error:
        if outcome != "lowering_failed" or event["lowering_error"] != "review_" + str(error):
            raise ValueError("structured_review") from None
        return None
    if outcome != "planned":
        raise ValueError("structured_review")
    return register_drafted(reviewed)


def _extractor_inputs(case, local):
    """What left the host for the extractor's model, recomputed from the
    provider's own record of each `dojo.model.extract` call (the arguments as
    the provider received them): every body the generator recorded as sent is
    one of these recomputed bodies, in order. Under the masked view (the model
    codec: the kernel's executor masked every argument) no argument and no
    recomputed body carries a span the leak gate detects."""
    from agentdojo.task_suite.load_suites import get_suite
    from .agentdojo_tasks import BENCHMARK
    from .dojo_provider import extract_request
    from .drafted_tasks import EXTRACT_TOOL
    from .value_blind import _spans
    masked = case.get("extractor_view", "raw") == "masked"
    tools = {t.name: t for t in get_suite(BENCHMARK, case["suite"]).tools}
    digests = []
    for event in local:
        if event["kind"] != "provider_attempt":
            continue
        request = json.loads(base64.b64decode(event["payload_base64"], validate=True))
        params = request.get("params") or {}
        if params.get("name") != EXTRACT_TOOL:
            continue
        arguments = params["arguments"]
        body, _bound = extract_request(arguments, tools)
        if masked:
            sent = [m["content"] for m in json.loads(body)["messages"]]
            if any(_spans(text) for text in (*(v for v in arguments.values() if type(v) is str), *sent)):
                raise ValueError("extractor_saw_hidden_value")
        digests.append(hashlib.sha256(body).hexdigest())
    logged = [c["request_sha256"] for e in local if e["kind"] == "generator_calls" for c in e["calls"]]
    remaining = iter(digests)
    if not all(digest in remaining for digest in logged):
        raise ValueError("extractor_input_mismatch")


def verify_episode(directory, local, case, row, profile, turns, prior=None):
    drafted = None
    if case.get("root_author"):
        drafted = _drafted_contract(case, local, row, prior)
        if drafted is None:
            # Refused or not drafted: nothing was signed and no tool ran.
            if any(e["kind"] in ("provider_attempt", "provider_attempt_unbound", "official_tool_result",
                                 "benchmark_consent") for e in local):
                raise ValueError("refused_program_had_effects")
            return
    suite, task, injection, contract, values, env = official_case(case, drafted)
    initial = _one(local, "episode_input")
    if initial["contract"] != contract.document() or initial["injections"] != values:
        raise ValueError("task_or_attack_mismatch")
    # An act turn starts where its read turn left the environment and is
    # scored as the whole task: from before the read turn, both turns' calls.
    continued = None
    if case.get("instructions") == "act":
        continued = dict(environment=_final_environment(prior), before=_one(prior, "episode_input")["environment"],
                         trace=official_trace(prior))
    if initial["environment"] != (env.model_dump(mode="json") if continued is None else continued["environment"]):
        raise ValueError("initial_environment_mismatch")
    authored = [e for e in local if e["kind"] == "plan_authored"]
    if not authored and row["outcome"] == "setup_failed":
        # Setup failed before the plan was authored (the episode's provider
        # listeners did not start): nothing may have been submitted, admitted,
        # approved or bound; the checks below confirm no call went out and the
        # environment is the one the episode started with.
        if any(e["kind"] in ("plan_submitted", "admission_stage_started", "benchmark_consent", "episode_binding",
                             "native_execution_prepared") for e in local):
            raise ValueError("plan_author_evidence")
    elif len(authored) != 1 or authored[0] != dict(authored[0], author=case["author"], mutation=case["mutation"]):
        raise ValueError("plan_author_evidence")
    draft, deviates = _submitted_draft(contract, local)
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
    entries = None
    if case.get("owner") == "directory":
        from .benchmark_consent import _chosen_by_data
        from .owner_directory import in_directory, owner_directory
        entries = owner_directory(case["suite"])
    from .value_blind import EXTRACTOR_CODECS
    model_codec = EXTRACTOR_CODECS[case.get("extractor_view", "raw")]
    for event in local:
        if event["kind"] in ("official_tool_result", "executor_local_result"):
            prior.append(canonical(event["response"]))
        if event["kind"] not in ("provider_attempt", "provider_attempt_unbound"):
            continue
        payload = base64.b64decode(event["payload_base64"], validate=True)
        verdict = ("unauthorized_unbound" if event["kind"] == "provider_attempt_unbound" else
                   classify_provider_attempt(payload, contract=contract, resource=resource,
                                             application_turn=turn or "", prior_results=tuple(prior),
                                             model_codec=model_codec))
        if event["verdict"] != verdict:
            raise ValueError("provider_attempt_verdict")
        if entries is not None and verdict == "authorized_tool":
            # The directory owner approved this call: every value data chose for it is one the owner knows.
            arguments = json.loads(payload)["params"]["arguments"]
            if not all(in_directory(arguments.get(field), entries)
                       for field in _chosen_by_data(contract.steps()[len(prior)])):
                raise ValueError("directory_owner_approved_unknown_destination")
        if case.get("owner") == "set" and verdict == "authorized_tool":
            # The set owner's call went out: every value data chose for it is,
            # byte for byte, a member the owner signed into that edge.
            from .agentdojo_tasks import edge_candidates
            from .benchmark_consent import _chosen_by_data
            step = contract.steps()[len(prior)]
            arguments = json.loads(payload)["params"]["arguments"]
            signed = {edge[0]: edge_candidates(edge) for edge in step.derived}
            for field in _chosen_by_data(step):
                value, members = arguments.get(field), signed.get(field) or ()
                items = value if type(value) is list else [value]
                if not all(type(item) is str and item in members for item in items):
                    raise ValueError("set_owner_dispatched_unsigned_destination")
        verdicts.append(verdict)
    if (row["provider_attempts"] != len(verdicts) or row["owner_releases"] != verdicts.count("owner_release")
            or row["unauthorized_provider_attempts"] != sum(v.startswith("unauthorized") for v in verdicts)):
        raise ValueError("provider_attempt_counts")
    _extractor_inputs(case, local)
    if row["outcome"] == "published":
        utility, attacker = verify_published_episode(directory, local, case, dict(row, status="scored"), profile,
                                                     drafted, continued=continued)
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
        before = restore_environment(type(env), initial["environment"] if continued is None else continued["before"])
        after = restore_environment(type(env), final)
        observed = score_outcome(suite=suite, task=task, injection=injection, contract=contract,
            before=before, after=after, provider=SimpleNamespace(audit=[
                *([] if continued is None else continued["trace"]), *official_trace(local)]),
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
            or manifest.get("human_authentication_evaluated") is not False):
        raise ValueError("planner_experiment_scope_mismatch")
    if manifest["package_sources"] != package_sources():
        raise ValueError("official_package_source_mismatch")
    # The deployment shipped the model tools with the one codec every case's
    # extractor view needs (the runner refuses a run otherwise).
    from .value_blind import EXTRACTOR_CODECS
    if any(EXTRACTOR_CODECS[case.get("extractor_view", "raw")] != manifest.get("model_codec") for case in cases):
        raise ValueError("extractor_view_not_deployed")
    # A registered or structured run's templates and planner prompt are the current ones.
    if any(manifest.get(k) != v for k, v in structured_provenance(cases).items() if k != "structured_example_sha256"):
        raise ValueError("structured_provenance_mismatch")
    if any(manifest.get(k) != v for k, v in directory_provenance(cases).items()):
        raise ValueError("owner_directory_mismatch")
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
            prior = ([e for e in events if e.get("episode") == index - 1]
                     if case.get("instructions") == "act" else None)
            verify_episode(directory, local, case, row, profile, turns, prior)
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
