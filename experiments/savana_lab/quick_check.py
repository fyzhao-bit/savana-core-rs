"""How closely `quick` follows a host: replay recorded host episodes through
its execution and compare.

For every episode a host executed, the recorded contract (the program the
owner's review accepted and the kernel ran) goes through `quick`'s execution
with the extractor answering exactly as it answered on the host. Each tool
call (its arguments and reply), each local answer, each owner refusal, the
outcome and the official oracle's verdicts must come out as the host
recorded them. AgentDojo's own nondeterminism is taken out first: the clock
(`create_file` stamps the time) and set order (calendar participants).

    python -m savana_lab quick-check u9b
    print(sl.quick_check("u9b"))
"""
from __future__ import annotations

import collections
from dataclasses import dataclass, field
import json

SAME = "same"
KERNEL_STOP = "the kernel stopped first (not modelled by quick)"
OLDER = "older architecture (a compute step or a guard answered by the provider)"
DIFFERENT = "DIFFERENT"
# AgentDojo stamps these with the current time.
VOLATILE = frozenset({"last_modified", "timestamp"})


@dataclass
class Check:
    name: str
    tally: collections.Counter = field(default_factory=collections.Counter)
    notes: list = field(default_factory=list)

    def __str__(self):
        compared = sum(n for k, n in self.tally.items() if k in (SAME, KERNEL_STOP, DIFFERENT))
        lines = [f"{self.name}: {self.tally[SAME]}/{compared} executed episodes the same as on the host"]
        lines += [f"  {kind}: {n}" for kind, n in sorted(self.tally.items()) if kind != SAME]
        lines += [f"  {note}" for note in self.notes]
        return "\n".join(lines)


class RecordedExtractor:
    """The quarantined extractor answering as it answered on the host."""

    def __init__(self, model, lines):
        self.model, self.lines, self.log = model, list(lines), []

    def __call__(self, **_request):
        self.log.append({})
        if not self.lines:
            raise RuntimeError("no_recorded_reply")
        line = self.lines.pop(0)
        if line is None:
            raise RuntimeError("recorded_failure")
        return line


def recorded_contract(document):
    """The DraftedContract a host ran, rebuilt from its recorded document."""
    from savana_bench.agentdojo_tasks import LIST, Step, register_drafted
    from savana_bench.drafted_tasks import DraftedContract
    steps = []
    for s in document["steps"]:
        derived = []
        for d in s["derived"]:
            edge = [d["field"], d["source_operation"], tuple(d["path"]), d["max_bytes"]]
            form = LIST if d.get("list") else (d["compute"]["op"], d["compute"]["amount"]) if d.get("compute") else None
            if form is not None or "candidates" in d:
                edge.append(form)
            if "candidates" in d:
                edge.append(tuple(d["candidates"]))
            derived.append(tuple(edge))
        values = tuple((k, tuple(v) if isinstance(v, list) else v) for k, v in s["values"].items())
        steps.append(Step(s["tool"], s["upstream_tool"], values, tuple(derived), s["payload_from"]))
    contract = DraftedContract(document["suite"], document["task"], document["prompt"], tuple(steps),
                               document["program"])
    if contract.document() != document:
        raise ValueError("recorded_contract")
    return register_drafted(contract)


def _norm(value):
    if isinstance(value, dict):
        return {k: _norm(v) for k, v in value.items() if k not in VOLATILE}
    if isinstance(value, list):
        items = [_norm(v) for v in value]
        return sorted(items, key=json.dumps) if all(isinstance(v, str) for v in items) else items
    if isinstance(value, str) and value[:1] in "[{":
        try:
            return _norm(json.loads(value))
        except ValueError:
            return value
    return value


def _calls(events):
    return [(e["kind"], e["operation"], e["tool"], _norm(e.get("arguments")),
             _norm({k: v for k, v in e["response"].items() if k != "id"}))
            for e in events if e["kind"] in ("official_tool_result", "executor_local_result")]


def _refusals(events):
    return [(e.get("clause"), e.get("reason")) for e in events if e["kind"] == "benchmark_consent"
            and e.get("decision") == "refuse" and e.get("purpose") == "tool_execution"]


def compare_episode(case, local, row):
    """(kind, detail) for one recorded episode, or None if it never executed."""
    from .quick import _execute
    initial = next((e for e in local if e["kind"] == "episode_input"), None)
    if initial is None:
        return None
    try:
        contract = recorded_contract(initial["contract"])
    except (ValueError, KeyError, TypeError) as error:
        return DIFFERENT, f"contract not rebuilt ({error})"
    older = any(e["kind"] == "official_tool_result" and (
        e["tool"] == "savana_compute_table"
        or str(e["response"]["result"]["content"][0]["text"]).startswith('"Skipped')) for e in local)
    lines = [json.loads(e["response"]["result"]["content"][0]["text"])["text"]
             if e["response"]["result"]["structuredContent"]["savana_status"] == "succeeded" else None
             for e in local if e["kind"] == "official_tool_result" and e["tool"] == "quarantined_extract"]
    ours = []
    outcome, utility, attacker = _execute(case, contract, RecordedExtractor(case["extractor_model"], lines),
                                          lambda kind, **data: ours.append(dict(kind=kind, **data)))
    score = next(e for e in ours if e["kind"] == "episode_score")
    recorded = (row["outcome"], row.get("utility") is True, row.get("observed_utility"),
                row.get("observed_attacker_success"))
    mine = (outcome, utility is True, score["observed_utility"], attacker)
    if _calls(local) == _calls(ours) and _refusals(local) == _refusals(ours) and recorded == mine:
        return SAME, None
    if older:
        return OLDER, None
    detail = f"host {recorded} quick {mine}"
    if (row["outcome"] == "no_publication" and row.get("stage") == "wait_publication"
            and (recorded[1], recorded[3]) == (mine[1], mine[3])):
        # The kernel stopped preparing calls (a check of its own) and the host
        # waited for a publication; quick's owner or oracle ended it later.
        return KERNEL_STOP, detail
    return DIFFERENT, detail


def check(*names, lab=None):
    """Replay every executed episode of the named runs' verified batches."""
    from .lab import Lab
    from .quick import _ensure_sdk
    from .report import Report
    from .results import VERIFIED, events
    lab = lab or Lab()
    _ensure_sdk(lab)
    report = Report.load(lab, *names)
    result = Check(report.name)
    for batch, state in report.states().items():
        if state != VERIFIED:
            result.tally["batch not verified (skipped)"] += 1
            continue
        found = events(lab.results, batch)
        cases = next(e for e in found if e["kind"] == "manifest")["cases"]
        for index, case in enumerate(cases):
            local = [e for e in found if e.get("episode") == index and e["kind"] != "episode_score"]
            row = next(e for e in found if e["kind"] == "episode_score" and e.get("episode") == index)
            compared = compare_episode(case, local, row)
            if compared is None:
                result.tally["not executed (refused before any call)"] += 1
                continue
            kind, detail = compared
            result.tally[kind] += 1
            if detail is not None:
                task = case["user"] + (f"+{case['injection']}" if case.get("injection") else "")
                result.notes.append(f"{kind}: {batch} episode {index} {case['suite']} {task}: {detail}")
    return result
