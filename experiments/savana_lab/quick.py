"""Quick try: one task in this process, in seconds, to tune a prompt, a model
or a review rule.

NOT EXPERIMENT EVIDENCE. There is no host, no kernel and no verifier. The
task is drafted, reviewed and structurally planned by the runner's own
functions (`planner_experiment.draft_reviewed`, `structured_contract`), with
the same models. The accepted program then runs here against the AgentDojo
environment, through the same provider adapters, step by step:

- each call's derived values are computed as the kernel computes them;
- every step is put to the same software owner's per-call rules
  (`benchmark_consent.judge_call`), each step asking as under the default
  disposition;
- the executor's local answers (compute steps, guards that do not hold) are
  the reference implementation's;
- the result is scored by the official oracle.

Not run: the kernel's own checks (compile, prepare, its G5 floor, the
intent-flow validators) and the owner's checks of the kernel's display. Those
can only stop a call, never add one; a model may also answer differently the
next time.

    import savana_lab as sl
    result = sl.quick(sl.U9, "travel", "user_task_13")
    print(result)                     # outcome, oracle verdict, each draft, the owner, each call
    for call in result.model_calls(): print(call)
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import os
import sys
import time

from .config import ConfigError, runner_cases
from .report import Episode

NOT_EVIDENCE = "QUICK TRY - no host, no kernel, no verifier: NOT experiment evidence"


@dataclass
class QuickResult:
    suite: str
    task: str
    spec: str
    outcome: str
    utility: bool | None
    attacker: bool | None
    seconds: float
    episode: Episode

    def why(self):
        lines = self.episode.why().splitlines()
        attack = "" if self.attacker is None else f", attacker success {self.attacker}"
        lines[0] = (f"{self.suite} {self.task}: outcome {self.outcome}, oracle utility {self.utility}{attack} "
                    f"({self.seconds:.1f} s)")
        for e in self.episode.of("quick_failed_call"):
            shown = {k: (v if len(str(v)) <= 160 else str(v)[:157] + "...") for k, v in e["arguments"].items()}
            lines.append(f"  failed call: {e['operation']}:{e['tool']} {json.dumps(shown, ensure_ascii=False)}")
        return "\n".join([NOT_EVIDENCE, *lines])

    def drafts(self):
        return self.episode.drafts()

    def answer(self):
        return self.episode.answer()

    def model_calls(self):
        return self.episode.model_calls()

    def __str__(self):
        return self.why()


def quick(config, suite, task, *, lab=None, keys=None, example=None, clients=None):
    """Run `task` (user_task_N, or user_task_N+injection_task_M) of `suite`
    under `config` in this process. `keys` ({provider: key}) default to the
    environment variables of `chat_models.KEY_VARIABLES`; `example` is the
    structured-planning example binary (default: the stored artifacts' for
    this checkout); `clients` replaces model clients by role (drafter /
    structural / generator; tests)."""
    from agentdojo.task_suite.load_suites import get_suite
    from savana_bench.agentdojo_tasks import BENCHMARK
    from savana_bench.drafted_tasks import ProgramRefused
    from savana_bench.planner_experiment import draft_reviewed, structured_contract, turn_request
    from savana_bench.structured_planning import StructuredError
    from savana_bench.value_blind import planner_request
    started = time.monotonic()
    spec = config.spec(suite, [task])
    cases = runner_cases(spec)
    if len(cases) != 1:
        raise ConfigError("instructions", "a quick try runs one turn; this request is a read and an act turn")
    case = cases[0]
    _ensure_sdk(lab)
    clients = dict(clients or {})
    clients.update(_clients(case, keys, needed=set(_roles(case)) - set(clients)))
    official = get_suite(BENCHMARK, suite)
    prompt = official.get_user_task_by_id(case["user"]).PROMPT
    request = turn_request(case, prompt, None)
    _request, bindings = planner_request(prompt, case["planner_view"])
    events, row = [], dict(outcome="not_attempted", stage=None)

    def emit(kind, **data):
        events.append(dict(kind=kind, episode=0, **data))

    def result(outcome, utility, attacker):
        return QuickResult(suite, task, spec, outcome, utility, attacker, time.monotonic() - started,
                           Episode("quick", 0, case, events, verified=False))

    def draft_program():
        return draft_reviewed(case, official=official, request=request, bindings=bindings,
                              drafter=clients.get("drafter"), emit=emit, row=row)
    session = None
    try:
        drafted = None if case.get("mapper") == "service" else draft_program()
        if case["root_author"] == "structured":
            from savana_bench.structured_planning import StructuredSession
            session = StructuredSession(example or _example(lab), clients["structural"])
            drafted = structured_contract(case, drafted, structured=session, structural=clients["structural"],
                                          draft_program=draft_program, emit=emit, row=row, job_id="quick-0",
                                          request=request)
    except (ProgramRefused, StructuredError, RuntimeError) as error:
        # Refused or failed before anything would be signed: nothing ran.
        outcome = row["outcome"] if row["outcome"] != "not_attempted" else "author_failed"
        attacker = False if case["injection"] else None
        emit("episode_score", outcome=outcome, stage=row.get("stage"),
             refusal=row.get("refusal") or row.get("structured_error") or str(error), utility=False,
             observed_utility=False, attacker_success=attacker)
        return result(outcome, False, attacker)
    finally:
        if session is not None:
            session.close()
    generator = clients.get("generator")
    calls_before = 0 if generator is None else len(generator.log)
    outcome, utility, attacker = _execute(case, drafted, generator, emit)
    if generator is not None:
        emit("generator_calls", calls=generator.log[calls_before:])
    return result(outcome, utility, attacker)


def _roles(case):
    """The model clients a case calls."""
    roles = []
    if case["root_author"] not in ("fixed", "registered") and case.get("mapper") != "template":
        roles.append("drafter")
    if case["root_author"] == "structured":
        roles.append("structural")
    roles.append("generator")
    return roles


def _clients(case, keys, needed):
    """The `needed` model clients of a case, each on its registered endpoint,
    with the runner's budgets for one episode."""
    if not needed:
        return {}
    from savana_bench.chat_models import KEY_VARIABLES, provider
    from savana_bench.drafted_tasks import MAX_STEPS
    from savana_bench.quarantined_generator import DeepSeekGenerator
    from savana_bench.root_drafter import DeepSeekRootDrafter
    from savana_bench.structured_planning import DeepSeekStructuralPlanner

    def key(name):
        if keys is not None and provider(name) in keys:
            return keys[provider(name)]
        variable = KEY_VARIABLES.get(provider(name), provider(name).upper() + "_API_KEY")
        if not os.environ.get(variable):
            raise ConfigError("keys", f"${variable} is not set (for model {name})")
        return os.environ[variable]
    out = {}
    if "drafter" in needed:
        drafts = case["max_drafts"]
        out["drafter"] = DeepSeekRootDrafter(key(case["planner_model"]), max_calls=drafts,
                                             max_input_bytes=drafts * 131072, model=case["planner_model"])
    if "structural" in needed:
        out["structural"] = DeepSeekStructuralPlanner(key(case["planner_model"]), max_calls=1,
                                                      model=case["planner_model"])
    if "generator" in needed:
        steps = MAX_STEPS + (1 if case.get("answer") == "final" else 0)
        out["generator"] = DeepSeekGenerator(key(case["extractor_model"]), max_calls=steps,
                                             max_input_bytes=steps * 98304, model=case["extractor_model"])
    return out


def _artifacts(lab):
    """(lab, the stored artifacts built from this checkout's Rust sources)."""
    from .lab import Lab
    lab = lab or Lab()
    git = lab.git()
    return lab, lab.store().for_stage(git, git.head())


def _example(lab):
    return _artifacts(lab)[1].example


def _ensure_sdk(lab):
    """`savana_core` (the kernel's leak gate and masking, through its Python
    binding) for structured planning and the masked views: the one installed,
    or else the stored artifacts' wheel, unpacked as the verifier unpacks it."""
    if importlib.util.find_spec("savana_core") is not None:
        return
    from .artifacts import ArtifactError
    try:
        lab, artifacts = _artifacts(lab)
    except ArtifactError:
        return  # a case that needs it fails with the import error
    sys.path.insert(0, str(lab.verifier(lab.shell()).packages(artifacts.wheel)))


def _request_id(number):
    """A kernel-shaped request id (`step-` and 64 hex digits): an earlier
    result fed whole into a later payload has the length it has on a host."""
    return "step-" + hashlib.sha256(b"savana-lab-quick-%d" % number).hexdigest()


def _underivable(contract, results):
    """Why the kernel cannot prepare the next step, or None. Before it
    prepares any step the kernel derives again every derived value of the
    whole program whose source result is in (policy-core
    `fused_planning::recover_inputs`); one that fails stops the task there,
    even before a step that derives nothing. (Its driver then retries
    without recording why, so a host episode waits out the publication
    timeout.)"""
    from savana_bench.agentdojo_tasks import edge_value
    for number, step in enumerate(contract.steps()):
        for edge in step.derived:
            if edge[1] <= len(results):
                try:
                    edge_value(results, edge)
                except (ValueError, LookupError) as error:
                    return (f"underivable: step {number + 1} {edge[0]} from step {edge[1]} result "
                            f"({type(error).__name__}: {error})")
    return None


def _execute(case, drafted, generator, emit):
    """The accepted program, step by step, against the case's AgentDojo
    environment: (outcome, oracle utility, attacker success or None)."""
    from savana_bench.agentdojo_provider import canonical, decode, response as mcp_response
    from savana_bench.agentdojo_tasks import (LOCAL_REQUEST_ID, edge_candidates, executor_local_text,
                                              expected_step_call, expected_wire_params)
    from savana_bench.benchmark_consent import _chosen_by_data, judge_call
    from savana_bench.dojo_catalog import CATALOG, SENTINELS, official_call
    from savana_bench.dojo_provider import dojo_provider
    from savana_bench.owner_directory import owner_directory
    from savana_bench.private_episode import PrivateOutcome
    from savana_bench.protected_agentdojo import official_case, score_outcome
    from savana_bench.value_blind import EXTRACTOR_CODECS, unmask_model_reply
    suite, task, injection, contract, values, env = official_case(case, drafted)
    before = env.model_copy(deep=True)
    emit("episode_input", contract=contract.document(), injections=values, environment=before.model_dump(mode="json"))
    provider = dojo_provider(suite, env, max_calls=len(contract.steps()), generator=generator)
    codec = EXTRACTOR_CODECS[case.get("extractor_view", "raw")]
    owner = case.get("owner")
    directory = owner_directory(case["suite"]) if owner == "directory" else None
    # Every result as the kernel retains it, and which ones its executor answered itself.
    results, local, outcome, stopped = [], set(), "published", None
    for number, step in enumerate(contract.steps()):
        stopped = _underivable(contract, results)
        if stopped is not None:
            outcome = "no_publication"
            break
        arguments = expected_step_call(contract, number, results)["arguments"]
        try:
            # The owner is asked for every step, in order (the default disposition).
            if owner == "strict" and _chosen_by_data(step):
                raise ValueError("consent_derived_destination")
            in_candidates = None
            if owner == "set":
                # What the kernel shows: whether data's choice is, byte for
                # byte, a member of the set signed into that edge.
                signed = {edge[0]: edge_candidates(edge) for edge in step.derived}
                in_candidates = {}
                for field in _chosen_by_data(step):
                    value, members = arguments.get(field), signed.get(field)
                    items = value if type(value) is list else [value]
                    in_candidates[field] = members is not None and all(
                        type(i) is str and i in members for i in items)
            judge_call(step, arguments, directory=directory, in_candidates=in_candidates, prior_results=results)
        except ValueError as refusal:
            emit("benchmark_consent", purpose="tool_execution", decision="refuse", clause=number + 1,
                 reason=str(refusal))
            outcome = "owner_refused"
            break
        emit("benchmark_consent", purpose="tool_execution", decision="approve", clause=number + 1)
        text = executor_local_text(contract, number, results)
        if text is not None:
            raw = mcp_response(LOCAL_REQUEST_ID, "succeeded", text)
            emit("executor_local_result", operation=number + 1, tool=step.tool, response=decode(raw))
            results.append(raw)
            local.add(number)
            continue
        if step.payload_from and step.payload_from - 1 in local:
            # The endpoint refuses it: a local answer's envelope carries the kernel's own id.
            outcome, stopped = "no_publication", "local_result_as_payload"
            break
        params, masker = expected_wire_params(contract, number, results, codec)
        raw = provider.exchange(canonical(dict(jsonrpc="2.0", id=_request_id(number + 1), method="tools/call",
                                               params=params)))
        status = decode(raw)["result"]["structuredContent"]["savana_status"]
        if status != "succeeded":
            # The endpoint reports an unknown outcome (the adapter refused the
            # arguments, or the tool failed) and nothing is released; a host
            # ends the episode there too (`step_failed`). (`quick_failed_call`
            # is not an event a host records: the call as it was sent, to see why.)
            error = provider.audit[-1].get("error")
            emit("official_tool_failed", operation=number + 1, tool=step.tool, status=status, error=error)
            emit("quick_failed_call", operation=number + 1, tool=step.tool, arguments=params["arguments"])
            outcome, stopped = "step_failed", f"step {number + 1} ({step.tool}) {status}: {error}"
            break
        retained = unmask_model_reply(masker, raw) if masker is not None else raw
        if any(t["operation"] == step.tool for t in CATALOG):
            _, official = official_call(step.tool, params["arguments"])
        else:
            official = {k: v for k, v in params["arguments"].items() if k not in SENTINELS}
        emit("official_tool_result", operation=number + 1, tool=step.upstream_tool, arguments=official,
             response=decode(retained))
        results.append(retained)
    after = provider.env
    if outcome == "published":
        payload = results[-1]
        if len(results) - 1 in local:
            # A local last answer is released with the kernel's own request id.
            payload = canonical(dict(decode(payload), id=_request_id(len(results))))
        emit("episode_observation", output_base64=base64.b64encode(payload).decode("ascii"))
        utility, attacker = score_outcome(suite=suite, task=task, injection=injection, contract=contract,
                                          before=before, after=after, provider=provider,
                                          outcome=PrivateOutcome("published", "complete", 0.0, None, payload))
        observed = utility
    else:
        # The oracle on the actual environment: a refusal is never utility,
        # an effect (an attacker's included) never hidden.
        observed, attacker = score_outcome(suite=suite, task=task, injection=injection, contract=contract,
                                           before=before, after=after, provider=provider, outcome=None)
        utility = False
    emit("episode_score", outcome=outcome, stage="execution", refusal=stopped, utility=utility,
         observed_utility=observed, attacker_success=attacker)
    return outcome, utility, attacker
