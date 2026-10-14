"""Reading a run's results: utility, task-by-task comparison, why a task
failed, and what each model was shown and answered.

Only batches the offline verifier passed are counted; a task in any other
batch is reported as missing, never as a failure or a success. Everything
here reads the exported evidence and changes nothing.

    rep = lab.report("u9b")
    print(rep.utility())
    print(rep.compare("u8s"))
    print(rep.why("travel", "user_task_13"))
    for call in rep.episode("travel", "user_task_13").model_calls(): print(call)
"""
from __future__ import annotations

import base64
import collections
from dataclasses import dataclass
import hashlib
import json
import re

from .plan import SUITES
from .results import VERIFIED, batch_state, events, rows

BATCH = re.compile(r"(?P<run>.+)-(?P<suite>banking|slack|travel|workspace)-(?P<k>[0-9]+)")


def _key(row):
    return (row["suite"], row["user"], row.get("injection"))


def _task(suite, task):
    user, _, injection = task.partition("+")
    return (suite, user, injection or None)


class Report:
    def __init__(self, lab, batches, name=None):
        self.lab, self.batches, self.name = lab, list(batches), name or ",".join(batches)

    @classmethod
    def load(cls, lab, *names):
        """The batches of runs by name: a savana_lab run's plan, or for a run
        the shell drivers made, every `<name>-<suite>-<k>` result directory."""
        batches = []
        for name in names:
            run = lab.results / "_lab" / name / "run.json"
            if run.is_file():
                batches += [b["name"] for b in json.loads(run.read_text())["plan"]["batches"]]
                continue
            found = sorted((p.name for p in lab.results.iterdir() if p.is_dir()
                            and (m := BATCH.fullmatch(p.name)) and m["run"] == name),
                           key=lambda n: (SUITES.index(BATCH.fullmatch(n)["suite"]), int(BATCH.fullmatch(n)["k"])))
            if not found:
                raise LookupError(f"no run or result batches named {name}")
            batches += found
        return cls(lab, batches, name="+".join(names))

    def states(self):
        return {b: batch_state(self.lab.results, b) for b in self.batches}

    def rows(self):
        """Every episode row of the verified batches, with its batch name."""
        out = []
        for batch, state in self.states().items():
            if state == VERIFIED:
                out += [dict(row, batch=batch) for row in rows(self.lab.results, batch)]
        return out

    def utility(self):
        return Utility(self.name, self.rows(), [b for b, s in self.states().items() if s != VERIFIED])

    def outcomes(self):
        return collections.Counter(row["outcome"] for row in self.rows())

    def compare(self, other):
        other = other if isinstance(other, Report) else Report.load(self.lab, other)
        mine = {_key(r): r for r in self.rows()}
        theirs = {_key(r): r for r in other.rows()}
        both = sorted(set(mine) & set(theirs), key=_order)
        return Comparison(self.name, other.name,
                          gained=[(k, mine[k], theirs[k]) for k in both
                                  if mine[k].get("utility") is True and theirs[k].get("utility") is not True],
                          lost=[(k, mine[k], theirs[k]) for k in both
                                if mine[k].get("utility") is not True and theirs[k].get("utility") is True],
                          same=len([k for k in both if (mine[k].get("utility") is True)
                                    == (theirs[k].get("utility") is True)]),
                          only_mine=sorted(set(mine) - set(theirs), key=_order),
                          only_theirs=sorted(set(theirs) - set(mine), key=_order))

    def episode(self, suite, task):
        """The episode of one task (`user_task_N` or `user_task_N+injection_task_M`)."""
        wanted = _task(suite, task)
        for batch in self.batches:
            found = events(self.lab.results, batch)
            if not found:
                continue
            cases = next(e for e in found if e["kind"] == "manifest")["cases"]
            for index, case in enumerate(cases):
                if (case["suite"], case["user"], case.get("injection")) == wanted:
                    local = [e for e in found if e.get("episode") == index]
                    return Episode(batch, index, case, local, self.states()[batch] == VERIFIED)
        raise LookupError(f"{suite} {task} is in none of {self.name}'s batches")

    def why(self, suite, task):
        return self.episode(suite, task).why()


def _order(key):
    suite, user, injection = key
    number = int(user.rsplit("_", 1)[1])
    return (SUITES.index(suite) if suite in SUITES else 9, number, injection or "")


@dataclass
class Utility:
    name: str
    rows: list
    unverified: list

    def by_suite(self):
        table = {}
        for row in self.rows:
            ok, total = table.get(row["suite"], (0, 0))
            table[row["suite"]] = (ok + (row.get("utility") is True), total + 1)
        return dict(sorted(table.items(), key=lambda kv: SUITES.index(kv[0])))

    def total(self):
        return (sum(r.get("utility") is True for r in self.rows), len(self.rows))

    def __str__(self):
        table = self.by_suite()
        ok, total = self.total()
        lines = [f"{self.name}: {ok}/{total} useful (official utility, verified batches only)"]
        lines += [f"  {suite:10s} {v[0]:3d}/{v[1]}" for suite, v in table.items()]
        if self.unverified:
            lines.append(f"  not counted (not verified): {', '.join(self.unverified)}")
        return "\n".join(lines)


@dataclass
class Comparison:
    mine: str
    theirs: str
    gained: list
    lost: list
    same: int
    only_mine: list
    only_theirs: list

    def __str__(self):
        def name(key):
            return f"{key[0]} {key[1].replace('user_task_', '')}" + (f"+{key[2]}" if key[2] else "")
        lines = [f"{self.mine} vs {self.theirs}: +{len(self.gained)} -{len(self.lost)}, {self.same} the same"]
        for title, entries in (("useful only in " + self.mine, self.gained),
                               ("useful only in " + self.theirs, self.lost)):
            if entries:
                lines.append(f"  {title}:")
                lines += [f"    {name(k):18s} {a['outcome']:16s} | {b['outcome']}" for k, a, b in entries]
        if self.only_mine or self.only_theirs:
            lines.append(f"  not compared (verified in only one): {len(self.only_mine)} + {len(self.only_theirs)}")
        return "\n".join(lines)


class Episode:
    def __init__(self, batch, index, case, local, verified):
        self.batch, self.index, self.case, self.events, self.verified = batch, index, case, local, verified
        self.score = next((e for e in local if e["kind"] == "episode_score"), {})

    def of(self, kind):
        return [e for e in self.events if e["kind"] == kind]

    def drafts(self):
        """Each draft the planner wrote, with the review's refusal of it (None if accepted)."""
        refusals = {e["attempt"]: e for e in self.of("program_refused")}
        return [dict(attempt=e["attempt"], program=e["program_text"], refusal=refusals.get(e["attempt"]))
                for e in sorted(self.of("root_drafted"), key=lambda e: e["attempt"])]

    def answer(self):
        """The text the owner received, or None if nothing was published."""
        for e in self.of("episode_observation"):
            if e.get("output_base64"):
                payload = json.loads(base64.b64decode(e["output_base64"]))
                text = payload["result"]["content"][0]["text"]
                try:
                    return json.loads(text).get("text", text)
                except (ValueError, AttributeError):
                    return text
        return None

    def model_calls(self):
        """What each model was shown and answered, in order:
        the drafting model's replies (each checked against its logged digest),
        the ordering model's view and reply, and each extraction's request and
        the value it returned (the extractor's raw reply is logged only as a
        digest). An extraction's source result is not in its recorded request:
        it is shown from the source step's result, and under the masked
        extractor view (`extract="masked"`) as `source_result_before_masking`,
        since the model received it with placeholders."""
        source_key = "source_result_before_masking" if self.case.get("extractor_view") == "masked" else "source_result"
        calls, results = [], {}
        for e in self.events:
            if e["kind"] in ("official_tool_result", "executor_local_result"):
                results[e["operation"]] = e["response"].get("result", {}).get("content", [{}])[0].get("text")
            if e["kind"] == "root_drafted":
                ok = hashlib.sha256(e["program_text"].encode()).hexdigest() == e.get("response_sha256")
                calls.append(dict(model="drafting", attempt=e["attempt"], reply=e["program_text"], digest_ok=ok))
            elif e["kind"] == "structured_planned":
                for call in e.get("planner_calls") or []:
                    calls.append(dict(model="ordering", shown=_ordering_view(e), reply=call.get("content")))
            elif e["kind"] == "official_tool_result" and e["tool"] == "quarantined_extract":
                arguments = e["arguments"]
                shown = {k: v for k, v in arguments.items() if v not in ("", None) and k != "model"}
                # SOURCE is the whole result of an earlier step (`4:computed`: step 4, a computation's input).
                source = str(arguments.get("source", "")).split(":")[0]
                if source.isdigit() and int(source) in results:
                    shown[source_key] = results[int(source)]
                calls.append(dict(model=f"extractor ({arguments.get('model')})", step=e["operation"], shown=shown,
                                  reply=results[e["operation"]]))
        return calls

    def why(self):
        s, case = self.score, self.case
        task = case["user"] + (f"+{case['injection']}" if case.get("injection") else "")
        lines = [f"{case['suite']} {task} ({self.batch}, episode {self.index}"
                 f"{'' if self.verified else ', batch NOT verified'}): outcome {s.get('outcome')}, "
                 f"utility {s.get('utility')}"]
        for key in ("stage", "refusal", "error_type", "error_errno", "error_code"):
            if s.get(key):
                lines.append(f"  {key}: {s[key]}")
        for draft in self.drafts():
            refusal = draft["refusal"]
            verdict = ("accepted" if refusal is None else
                       f"refused: {refusal['reason']} (step {refusal.get('step')}, field {refusal.get('field')})")
            lines.append(f"  draft {draft['attempt']}: {verdict}")
        for e in self.of("structured_planned"):
            detail = e.get("error") or e.get("lowering_error") or ""
            lines.append(f"  structured planning: {e.get('outcome')} order {e.get('order')}"
                         f"{' (reordered)' if e.get('order_changed') else ''} {detail}".rstrip())
        refused = [e for e in self.of("benchmark_consent") if e.get("decision") != "approve"]
        votes = self.of("benchmark_consent")
        if votes:
            lines.append("  owner: " + ("approved every request" if not refused else
                                        "; ".join(f"refused {e.get('purpose')} clause {e.get('clause')}: "
                                                  f"{e.get('reason')}" for e in refused)))
        calls = [e for e in self.events if e["kind"] in ("official_tool_result", "executor_local_result")]
        if calls:
            lines.append(f"  tool calls: {len(calls)} ("
                         + ", ".join(f"{e['operation']}:{e['tool']}" for e in calls) + ")")
        answer = self.answer()
        if answer is not None:
            lines.append(f"  answer: {answer}")
        return "\n".join(lines)


def _ordering_view(event):
    try:
        from savana_bench.structured_planning import planner_view
        from savana_bench.structured_wire import decode_structural_request
        return planner_view(decode_structural_request(bytes.fromhex(event["planner_request"])))[1]
    except Exception as error:  # an older run's wire format: show what was logged
        return f"<request {event.get('planner_request', '')[:32]}... not decoded: {type(error).__name__}>"
