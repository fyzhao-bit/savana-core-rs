"""Registered task programs for the structured-planning evaluation (arm T).

A template is the program the owner's CURRENT fixed review
(`drafted_tasks.review_program`) accepts from one recorded G12 drafting
episode, registered unedited. Each task's recorded drafts are replayed in
order exactly as the drafting stage judges them: the first draft the review
accepts ends drafting and is the template; a final policy refusal
(`root_drafter.NON_RETRYABLE`) ends it early; a task whose recorded drafts are
all refused has none (no planner is asked again).

Only the owner's request (the official task prompt), the suite's tool names,
the recorded draft texts and the runs' hash chains are used: never a tool
result, an environment, a utility or oracle score, or a ground truth. Every
other line of a source log is only hashed (to check the chain) and dropped.
Each template records the source run's audit head and the exact logged draft
it is, so it can be traced back without trusting this file.

    python -m savana_bench.structured_templates build --results <dir>
"""
import argparse
import hashlib
import json
from pathlib import Path

from .agentdojo_provider import canonical

SCHEMA = "savana-structured-templates-v1"
REGISTRY = Path(__file__).parent / "data" / "structured_templates.json"
# The G12 drafting runs (experiments/AGENTDOJO-G12-20261007.zh-CN.md).
SOURCE_PREFIX = "g12k-"
DEFAULT_RESULTS = Path(__file__).resolve().parents[1] / "results" / "local-container-20260930"
# The only kinds read from a source log.
KEPT = ("manifest", "root_drafted", "program_refused")


def _source_log(run):
    """(kept events, identity) of one run directory: the hash chain is
    re-derived over every line and must end at the recorded completion."""
    raw = (run / "events.jsonl").read_bytes()
    previous, kept, count = "0" * 64, [], 0
    for seq, line in enumerate(raw.splitlines()):
        row = json.loads(line)
        digest = row.pop("sha256")
        if row["seq"] != seq or row["previous"] != previous or hashlib.sha256(canonical(row)).hexdigest() != digest:
            raise ValueError("broken_audit_chain")
        previous, count = digest, count + 1
        if row["kind"] in KEPT:
            kept.append(dict(row, sha256=digest))
    if json.loads((run / "completion.json").read_bytes()) != dict(audit_head=previous, event_count=count):
        raise ValueError("completion_digest_mismatch")
    if not kept or kept[0]["kind"] != "manifest" or kept[0]["seq"] != 0:
        raise ValueError("source_manifest")
    return kept, dict(batch=run.parent.name, run=run.name, audit_head=previous, event_count=count,
                      events_sha256=hashlib.sha256(raw).hexdigest())


def replay(case, drafts):
    """The owner's current review over one episode's recorded drafts, in
    order -> (draft event, contract) of the first accepted draft, or
    (None, refusal code)."""
    from agentdojo.task_suite.load_suites import get_suite
    from .agentdojo_tasks import BENCHMARK
    from .drafted_tasks import ProgramRefused, parse_program_text, review_program
    from .root_drafter import NON_RETRYABLE
    from .value_blind import planner_request
    official = get_suite(BENCHMARK, case["suite"])
    prompt = official.get_user_task_by_id(case["user"]).PROMPT
    _request, bindings = planner_request(prompt, case.get("planner_view", "request"))
    reason = "not_drafted"
    for event in drafts:
        if hashlib.sha256(event["program_text"].encode()).hexdigest() != event["response_sha256"]:
            raise ValueError("program_text_digest")
        try:
            contract = review_program(suite=case["suite"], suite_tools={t.name for t in official.tools},
                                      task_id=case["user"], prompt=prompt,
                                      program=parse_program_text(event["program_text"]), bindings=bindings,
                                      extractor_model=case.get("extractor_model", "deepseek-flash"),
                                      derived_destinations=case.get("review") == "derived")
        except ProgramRefused as error:
            reason = str(error)
            if reason in NON_RETRYABLE:
                break
            continue
        return event, contract
    return None, reason


def build(results):
    """The registry document from every G12 run under `results`."""
    from .drafted_tasks import parse_program_text, review_policy
    templates, excluded, drafts_seen = [], [], 0
    batches = sorted(p for p in Path(results).iterdir() if p.is_dir() and p.name.startswith(SOURCE_PREFIX))
    if not batches:
        raise ValueError("no_source_runs")
    for batch in batches:
        runs = [p for p in batch.iterdir() if p.is_dir() and (p / "events.jsonl").is_file()]
        if len(runs) != 1:
            raise ValueError("one_run_per_batch")
        kept, identity = _source_log(runs[0])
        manifest = kept[0]
        for episode, case in enumerate(manifest["cases"]):
            if case.get("root_author") != "deepseek" or case.get("planner_view", "request") != "request":
                raise ValueError("source_case_scope")
            drafts = [e for e in kept if e["kind"] == "root_drafted" and e["episode"] == episode]
            if [e["attempt"] for e in drafts] != list(range(1, len(drafts) + 1)):
                raise ValueError("source_draft_order")
            drafts_seen += len(drafts)
            event, outcome = replay(case, drafts)
            key = dict(suite=case["suite"], user=case["user"])
            if event is None:
                excluded.append(dict(key, drafts=len(drafts), reason=outcome))
                continue
            program = parse_program_text(event["program_text"])
            templates.append(dict(key, program=program,
                                  program_sha256=hashlib.sha256(canonical(program)).hexdigest(),
                                  contract_sha256=outcome.digest(),
                                  source=dict(identity, episode=episode, attempt=event["attempt"],
                                              drafts=len(drafts), seq=event["seq"], event_sha256=event["sha256"],
                                              program_text_sha256=event["response_sha256"],
                                              planner_model=case["planner_model"])))
    order = lambda item: (item["suite"], int(item["user"].rpartition("_")[2]))
    keys = [(t["suite"], t["user"]) for t in templates + excluded]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate_source_task")
    return dict(schema=SCHEMA, source=SOURCE_PREFIX.rstrip("-"), drafts=drafts_seen,
                review_policy_sha256=hashlib.sha256(canonical(review_policy())).hexdigest(),
                templates=sorted(templates, key=order), excluded=sorted(excluded, key=order))


def encode_registry(registry):
    return (json.dumps(registry, ensure_ascii=False, sort_keys=True, indent=1) + "\n").encode()


def load_registry(path=REGISTRY):
    """The committed registry, each program checked against its digest."""
    registry = json.loads(Path(path).read_bytes())
    if type(registry) is not dict or registry.get("schema") != SCHEMA:
        raise ValueError("structured_registry_schema")
    for item in registry["templates"]:
        if hashlib.sha256(canonical(item["program"])).hexdigest() != item["program_sha256"]:
            raise ValueError("structured_registry_digest")
    return registry


def template(registry, suite, user):
    """The registered program of one task (KeyError: the task has none)."""
    for item in registry["templates"]:
        if (item["suite"], item["user"]) == (suite, user):
            return item
    raise KeyError("no_registered_template")


def template_number(registry, suite, user):
    """A registered template's id: its 1-based place in the registry."""
    return registry["templates"].index(template(registry, suite, user)) + 1


def program_text(registry, suite, user):
    """The exact text a registered author submits for this task."""
    return canonical(template(registry, suite, user)["program"]).decode("utf-8")


def registry_sha256(path=REGISTRY):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def summary(registry):
    by_suite, reasons = {}, {}
    for item in registry["templates"]:
        by_suite[item["suite"]] = by_suite.get(item["suite"], 0) + 1
    for item in registry["excluded"]:
        reasons[item["reason"]] = reasons.get(item["reason"], 0) + 1
    return dict(tasks=len(registry["templates"]) + len(registry["excluded"]), drafts=registry["drafts"],
                templates=len(registry["templates"]), by_suite=by_suite, excluded=reasons,
                registry_sha256=hashlib.sha256(encode_registry(registry)).hexdigest())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("build", help="Replay the current review over the recorded G12 drafts")
    command.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    command.add_argument("--output", type=Path, default=REGISTRY)
    args = parser.parse_args()
    registry = build(args.results)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(encode_registry(registry))
    print(json.dumps(summary(registry), indent=2, sort_keys=True))
