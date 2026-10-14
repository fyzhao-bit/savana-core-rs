"""Structured planning end to end (F5 Phase 2).

Three arms ran on fresh hosts, at most 9 benign AgentDojo tasks a batch:

* T (`+author=structured+mapper=template`): the task's registered template is
  the private mapper's program; the DeepSeek structural planner orders it
  through agentd's pipeline, and the lowered program is reviewed again and run;
* R (`+author=registered`): the same template run as registered, the paired
  control (its batches interleaved with T's);
* D (`+drafts=3+author=structured+mapper=deepseek`): the planner drafts as in
  G12 and the reviewed draft goes through the same pipeline.

Per episode, from its own evidence: the outcome, the official utility, and for
a structured episode the order agentd accepted, whether it changed, and
whether a write moved across a live-state call no edge ties it to
(`write_reordered`, recomputed from the reviewed program and the recorded
order). Only batches whose offline verification passed are counted.

Usage, from ``experiments/``::

    python -m analysis.structured_planning --results results/local-container-20260930
"""
import argparse
import collections
import glob
import json
import os
import statistics

ARMS = dict(T="f5t", R="f5r", D="f5d")
G12 = "g12k"
SUITES = ("banking", "slack", "travel", "workspace")


def _events(run):
    with open(os.path.join(run, "events.jsonl")) as handle:
        return [json.loads(line) for line in handle]


def batches(results, prefix):
    """(batch name, run directory, offline verification) of every verified batch."""
    found = []
    for batch in sorted(glob.glob(os.path.join(results, prefix + "-*"))):
        verification = os.path.join(batch, "offline-verification.json")
        runs = [p for p in glob.glob(os.path.join(batch, "*")) if os.path.isfile(os.path.join(p, "events.jsonl"))]
        if not os.path.isfile(verification) or not os.path.getsize(verification) or len(runs) != 1:
            continue
        with open(verification) as handle:
            found.append((os.path.basename(batch), runs[0], json.load(handle)))
    return found


def _reviewed_program(case, drafted):
    """The program the runner handed the mapper: the owner's review of the
    accepted (last) draft, as registered."""
    from agentdojo.task_suite.load_suites import get_suite
    from savana_bench.agentdojo_tasks import BENCHMARK, register_drafted
    from savana_bench.drafted_tasks import parse_program_text, review_program
    from savana_bench.value_blind import planner_request
    official = get_suite(BENCHMARK, case["suite"])
    prompt = official.get_user_task_by_id(case["user"]).PROMPT
    _request, bindings = planner_request(prompt, case.get("planner_view", "request"))
    contract = review_program(suite=case["suite"], suite_tools={t.name for t in official.tools},
                              task_id=case["user"], prompt=prompt,
                              program=parse_program_text(drafted[-1]["program_text"]), bindings=bindings,
                              extractor_model=case.get("extractor_model", "deepseek-flash"),
                              derived_destinations=case.get("review") == "derived")
    return json.loads(register_drafted(contract).program)


def episodes(results, prefix):
    """One record per episode of every verified batch with this prefix."""
    from savana_bench.structured_planning import eval_catalog, program_to_workflow, valid_orders, write_reordered
    records = []
    for name, run, verification in batches(results, prefix):
        events = _events(run)
        manifest, summary = events[0], events[-1]
        if manifest["kind"] != "manifest" or summary["kind"] != "summary":
            raise ValueError("run_evidence")
        by_episode = collections.defaultdict(list)
        for event in events:
            if "episode" in event:
                by_episode[event["episode"]].append(event)
        for row in summary["summary"]["rows"]:
            local = by_episode[row["episode"]]
            record = dict(batch=name, suite=row["suite"], user=row["user"], outcome=row["outcome"],
                          utility=row.get("utility") is True, drafts=row.get("drafts"),
                          refusal=row.get("refusal"), structured_error=row.get("structured_error"),
                          provider_attempts=row.get("provider_attempts", 0),
                          unauthorized=row.get("unauthorized_provider_attempts", 0),
                          seconds=row.get("episode_seconds"))
            planned = [e for e in local if e["kind"] == "structured_planned"]
            if planned:
                event, = planned
                calls = event["planner_calls"]
                record.update(structured=event["outcome"], order=event.get("order"),
                              order_changed=event.get("order_changed"), planner_calls=len(calls),
                              prompt_tokens=sum((c.get("usage") or {}).get("prompt_tokens") or 0 for c in calls),
                              completion_tokens=sum((c.get("usage") or {}).get("completion_tokens") or 0
                                                    for c in calls))
                drafted = [e for e in local if e["kind"] == "root_drafted"]
                conversion = program_to_workflow(_reviewed_program(row, drafted), eval_catalog(row["suite"]),
                                                 salt=bytes.fromhex(event["salt"]))
                record.update(valid_orders=valid_orders(conversion), steps=len(conversion.workflow.nodes),
                              write_reordered=(write_reordered(conversion, event["order"])
                                               if event.get("order") else None))
            records.append(record)
        groups = verification["groups"]
        if sum(g["planned"] for g in groups.values()) != len(summary["summary"]["rows"]):
            raise ValueError("verification_rows")
    return records


def safety(results, prefix):
    """The offline verifier's per-batch counts, summed."""
    keys = ("planned", "published", "utility_successes", "kernel_blocked", "owner_refused", "programs_refused",
            "unknown", "plans_deviating_from_reviewed", "provider_attempts", "unauthorized_provider_attempts",
            "official_attacker_successes")
    total = dict.fromkeys(keys, 0)
    count = 0
    for _name, _run, verification in batches(results, prefix):
        count += 1
        for group in verification["groups"].values():
            for key in keys:
                total[key] += group.get(key, 0)
    return dict(total, batches=count)


def g12_utility(results):
    """G12's per-task utility (drafted, 3 drafts, same planner)."""
    return {(r["suite"], r["user"]): r["utility"] for r in episodes(results, G12)}


def paired(t_rows, r_rows):
    """T and R joined on the task."""
    r_by_task = {(r["suite"], r["user"]): r for r in r_rows}
    pairs = []
    for t in t_rows:
        r = r_by_task.get((t["suite"], t["user"]))
        if r is not None:
            pairs.append((t, r))
    return pairs


def _counts(rows):
    return dict(tasks=len(rows), utility=sum(r["utility"] for r in rows),
                outcomes=dict(collections.Counter(r["outcome"] for r in rows)))


def report(results):
    arms = {arm: episodes(results, prefix) for arm, prefix in ARMS.items()}
    out = dict(arms={arm: _counts(rows) for arm, rows in arms.items()},
               safety={arm: safety(results, prefix) for arm, prefix in ARMS.items()})
    pairs = paired(arms["T"], arms["R"])
    split = collections.defaultdict(lambda: collections.Counter())
    discordant = []
    for t, r in pairs:
        kind = "single_order" if t.get("valid_orders", 1) == 1 else (
            "order_changed" if t.get("order_changed") else "several_orders_kept")
        if t.get("structured") not in (None, "planned"):
            kind = "structured_refused"
        cell = split[kind]
        cell["pairs"] += 1
        cell["T"] += t["utility"]
        cell["R"] += r["utility"]
        cell["both"] += t["utility"] and r["utility"]
        cell["T_only"] += t["utility"] and not r["utility"]
        cell["R_only"] += r["utility"] and not t["utility"]
        if t["utility"] != r["utility"]:
            discordant.append(dict(suite=t["suite"], user=t["user"], kind=kind, T=t["utility"], R=r["utility"],
                                   T_outcome=t["outcome"], R_outcome=r["outcome"], order=t.get("order"),
                                   write_reordered=t.get("write_reordered")))
    # Episode wall time: what the structured stage adds on top of running the same template.
    timed = [(t["seconds"], r["seconds"]) for t, r in pairs if t["seconds"] is not None and r["seconds"] is not None]
    out["paired"] = dict(pairs=len(pairs), by_kind={k: dict(v) for k, v in split.items()}, discordant=discordant,
                         seconds=dict(pairs=len(timed),
                                      T_median=statistics.median(t for t, _r in timed) if timed else None,
                                      R_median=statistics.median(r for _t, r in timed) if timed else None,
                                      difference_median=(statistics.median(t - r for t, r in timed)
                                                         if timed else None)))
    structured = [r for arm in ("T", "D") for r in arms[arm] if r.get("structured")]
    out["structured"] = {arm: dict(
        jobs=sum(1 for r in arms[arm] if r.get("structured")),
        outcomes=dict(collections.Counter(r["structured"] for r in arms[arm] if r.get("structured"))),
        order_changed=sum(bool(r.get("order_changed")) for r in arms[arm]),
        several_orders=sum(r.get("valid_orders", 1) > 1 for r in arms[arm] if r.get("structured")),
        write_reordered=[(r["suite"], r["user"], r["order"]) for r in arms[arm] if r.get("write_reordered")],
        planner_calls=sum(r.get("planner_calls", 0) for r in arms[arm]),
        prompt_tokens=sum(r.get("prompt_tokens", 0) for r in arms[arm]),
        completion_tokens=sum(r.get("completion_tokens", 0) for r in arms[arm])) for arm in ("T", "D")}
    out["structured_total_jobs"] = len(structured)
    g12 = g12_utility(results)
    by_suite = {}
    for suite in SUITES:
        d = [r for r in arms["D"] if r["suite"] == suite]
        by_suite[suite] = dict(D=sum(r["utility"] for r in d), D_tasks=len(d),
                               G12=sum(v for (s, _u), v in g12.items() if s == suite),
                               G12_tasks=sum(1 for s, _u in g12 if s == suite))
    changed = [r for r in arms["D"] if r.get("order_changed")]
    out["drafted"] = dict(by_suite=by_suite,
                          order_changed=dict(tasks=len(changed), utility=sum(r["utility"] for r in changed),
                                             g12_utility=sum(bool(g12.get((r["suite"], r["user"])))
                                                             for r in changed)),
                          order_kept=dict(tasks=sum(1 for r in arms["D"] if r.get("structured") == "planned"
                                                    and not r.get("order_changed")),
                                          utility=sum(r["utility"] for r in arms["D"]
                                                      if r.get("structured") == "planned"
                                                      and not r.get("order_changed"))))
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", default="results/local-container-20260930")
    args = parser.parse_args()
    print(json.dumps(report(args.results), indent=1, sort_keys=True, default=list))
