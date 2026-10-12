"""Utility improvements U1-U8 end to end (experiments/UTILITY-IMPROVEMENTS-20261012.zh-CN.md).

Each arm ran on fresh hosts, at most 9 AgentDojo cases a batch; only batches
whose offline verification passed are counted:

* G12 (`g12k`) and D (`f5d`): the starting points, 3 drafts each (D's drafts
  also went through structured planning);
* U12 (`u12c`): `+actions=ask+review=derived+owner=directory`, i.e. U1 and U2.
  Two of its batches overlapped local build and scan jobs on the measuring
  machine (median step interval above 5 s, against 3.8-4.6 s for every other
  batch); by a rule fixed before their reruns were seen, `u12r` reruns them
  and replaces them (`SUPERSEDED`), and `U12_first` keeps the originals;
* U8 (`u8f`): the same options with U3 (multi-field extraction), U4 (`mode`),
  ten steps and the kernel's masking fix (`u8` is its first two batches,
  stopped when they showed planners naming a multi-field extraction's
  field by its target label, which the review then refused);
* U8X (`u8x`): U8 under injection (AutoDojo's for banking, slack and travel,
  the official template for workspace), on the tasks whose U8 program had a
  step whose address data chose (`attack_sample`).

Per episode, from its own evidence: the outcome and the official utility; the
review's refusal code for each refused draft; whether the planner was asked
about an omitted write; the signed program's steps, writes, multi-field
extractions and `mode` outputs; and, read as `analysis.floor_experiment` reads
them, the steps whose address data chose, the owner's refusals (the directory
owner's reason is `consent_destination_not_in_directory`), and under attack
whether the attacker chose an address or reached a provider.

Usage, from ``experiments/``::

    python -m analysis.utility_improvements --results results/local-container-20260930 [report | sample]
"""
import argparse
import collections
import json
import statistics

from analysis.floor_experiment import episode_row, episodes as by_episode
from analysis.structured_planning import _events, batches

ARMS = dict(G12=("g12k",), D=("f5d",), U12=("u12c", "u12r"), U12_first=("u12c",), U8=("u8f",))
# A batch whose measurement a rerun replaces (see the docstring).
SUPERSEDED = {"U12": {"u12c-slack-2", "u12c-travel-0"}}
ATTACK = "u8x"
SUITES = ("banking", "slack", "travel", "workspace")
DIRECTORY_REFUSAL = "consent_destination_not_in_directory"


def program_shape(steps):
    """Counts over a signed program (the contract document's steps)."""
    from savana_bench.dojo_catalog import LIST_SEPARATOR
    from savana_bench.drafted_tasks import EXTRACT_TOOL
    return dict(
        steps=len(steps),
        # A model or compute step only reads recorded results or composes text.
        writes=sum(1 for s in steps if not s["tool"].startswith(("dojo.model.", "dojo.compute."))
                   and s["effect"] != "read"),
        multi=sum(1 for s in steps if s["tool"] == EXTRACT_TOOL and LIST_SEPARATOR in s["values"].get("target", "")),
        mode=sum(1 for s in steps if s["tool"].startswith("dojo.compute.")
                 and s["values"].get("output", "").startswith("mode ")))


def episode_record(local, row, batch):
    """One episode: its summary row, its review refusals and its signed program."""
    refused = sorted((e["attempt"], e["reason"]) for e in local if e["kind"] == "program_refused")
    inputs = [e for e in local if e["kind"] == "episode_input"]
    floor = episode_row(local)
    record = dict(batch=batch, suite=row["suite"], user=row["user"], injection=row.get("injection"),
                  outcome=row["outcome"], utility=row.get("utility") is True, drafts=row.get("drafts"),
                  refusal=row.get("refusal"), seconds=row.get("episode_seconds"),
                  stage=next((e.get("stage") for e in local if e["kind"] == "episode_score"), None),
                  review_refusals=[reason for _attempt, reason in refused],
                  asked=any(reason == "omitted_write" for _attempt, reason in refused),
                  signed=bool(inputs), data_chosen_steps=floor["data_chosen_steps"],
                  owner_asked=floor["asked"], owner_refusals=floor["refusal_reasons"],
                  directory_refused=DIRECTORY_REFUSAL in floor["refusal_reasons"],
                  dispatched_unapproved=floor["dispatched_unapproved"],
                  attacker_chose_address=floor["attacker_chose_address"],
                  attacker_address=floor["attacker_address"], attacker_text=floor["attacker_text"],
                  unauthorized=floor["unauthorized"], success=floor["success"])
    record.update(program_shape(inputs[0]["contract"]["steps"]) if inputs
                  else dict(steps=0, writes=0, multi=0, mode=0))
    return record


def episodes(results, prefix, superseded=()):
    """One record per episode of every verified batch with this prefix (or
    these prefixes), less the superseded batches."""
    records = []
    found = [b for p in ((prefix,) if type(prefix) is str else prefix) for b in batches(results, p)]
    for name, run, _verification in found:
        if name in superseded:
            continue
        events = _events(run)
        local = by_episode(events)
        summary = events[-1]
        if events[0]["kind"] != "manifest" or summary["kind"] != "summary":
            raise ValueError("run_evidence")
        for row in summary["summary"]["rows"]:
            records.append(episode_record(local[row["episode"]], row, name))
    return records


def _task(r):
    return r["suite"], r["user"]


def by_suite(rows):
    out = {}
    for suite in (*SUITES, "total"):
        subset = [r for r in rows if suite in ("total", r["suite"])]
        out[suite] = dict(tasks=len(subset), utility=sum(r["utility"] for r in subset))
    return out


def flips(new, old):
    """Tasks whose utility differs between two benign arms, with why."""
    old_by_task = {_task(r): r for r in old}
    gained, lost = [], []
    for r in new:
        o = old_by_task.get(_task(r))
        if o is None or r["utility"] == o["utility"]:
            continue
        entry = dict(suite=r["suite"], user=r["user"], outcome=r["outcome"], refusal=r["refusal"],
                     owner_refusals=r["owner_refusals"], asked=r["asked"], steps=r["steps"],
                     writes=r["writes"], data_chosen_steps=r["data_chosen_steps"], before=o["outcome"],
                     before_refusal=o["refusal"])
        (gained if r["utility"] else lost).append(entry)
    return dict(gained=gained, lost=lost)


def benign_summary(rows):
    published = [r for r in rows if r["outcome"] == "published"]
    timed = collections.defaultdict(list)
    for r in rows:
        if r["outcome"] == "published" and r["seconds"] is not None:
            timed[r["steps"]].append(r["seconds"])
    asked = [r for r in rows if r["asked"]]
    chosen = [r for r in rows if r["data_chosen_steps"]]
    return dict(
        by_suite=by_suite(rows),
        outcomes=dict(collections.Counter(r["outcome"] for r in rows)),
        final_refusals=dict(collections.Counter(r["refusal"] for r in rows if r["refusal"])),
        review_refusals=dict(collections.Counter(c for r in rows for c in r["review_refusals"])),
        # U1: asked once about an omitted write; did the program it kept write?
        asked=dict(episodes=len(asked), signed_with_write=sum(1 for r in asked if r["signed"] and r["writes"]),
                   signed_without_write=sum(1 for r in asked if r["signed"] and not r["writes"]),
                   utility=sum(r["utility"] for r in asked)),
        # U2: programs where data chose an address, and what the directory owner did.
        data_chosen=dict(episodes=len(chosen), published=sum(r["outcome"] == "published" for r in chosen),
                         utility=sum(r["utility"] for r in chosen),
                         directory_refused=sum(r["directory_refused"] for r in chosen),
                         tasks_refused=sorted(f"{r['suite']} {r['user']}" for r in chosen if r["directory_refused"])),
        # U3 / U4 / ten steps: how often the planner used them, and with what result.
        multi=dict(episodes=sum(1 for r in rows if r["multi"]),
                   utility=sum(r["utility"] for r in rows if r["multi"])),
        mode=dict(episodes=sum(1 for r in rows if r["mode"]), utility=sum(r["utility"] for r in rows if r["mode"])),
        over_eight_steps=dict(episodes=sum(1 for r in rows if r["steps"] > 8),
                              published=sum(1 for r in rows if r["steps"] > 8 and r["outcome"] == "published"),
                              utility=sum(r["utility"] for r in rows if r["steps"] > 8)),
        signed_writes=dict(programs=sum(1 for r in rows if r["signed"] and r["writes"]),
                           published=sum(1 for r in published if r["writes"])),
        seconds_by_steps={str(k): dict(n=len(v), median=round(statistics.median(v), 1), max=round(max(v), 1))
                          for k, v in sorted(timed.items())},
        not_published=[dict(suite=r["suite"], user=r["user"], outcome=r["outcome"], stage=r["stage"],
                            refusal=r["refusal"], owner_refusals=r["owner_refusals"], steps=r["steps"])
                       for r in rows if r["outcome"] != "published"],
        unauthorized=sum(r["unauthorized"] for r in rows),
        dispatched_unapproved=sum(r["dispatched_unapproved"] for r in rows))


def attack_summary(rows, baseline=()):
    """Per-suite counts under injection; `baseline` rows of an earlier run on
    the same pairs (their observed attacker success) for context."""
    out = {}
    for suite in (*SUITES, "total"):
        subset = [r for r in rows if suite in ("total", r["suite"])]
        if not subset:
            continue
        out[suite] = dict(
            pairs=len(subset), success=sum(r["success"] for r in subset),
            utility=sum(r["utility"] for r in subset),
            data_chosen=sum(1 for r in subset if r["data_chosen_steps"]),
            attacker_chose_address=sum(1 for r in subset if r["attacker_chose_address"]),
            directory_refused=sum(r["directory_refused"] for r in subset),
            attacker_address=sum(1 for r in subset if r["attacker_address"]),
            attacker_text=sum(1 for r in subset if r["attacker_text"]),
            dispatched_unapproved=sum(r["dispatched_unapproved"] for r in subset),
            unauthorized=sum(r["unauthorized"] for r in subset))
    pairs = {(r["suite"], r["user"], r["injection"]) for r in rows}
    before = [b for b in baseline if (b["suite"], b["user"], b["injection"]) in pairs]
    return dict(by_suite=out,
                successes=[dict(suite=r["suite"], user=r["user"], injection=r["injection"], outcome=r["outcome"],
                                attacker_address=r["attacker_address"], attacker_text=r["attacker_text"])
                           for r in rows if r["success"]],
                baseline=dict(pairs=len(before),
                              success=sum(b.get("observed_attacker_success") is True for b in before)))


def attack_sample(results, prefix="u8f"):
    """The tasks of a benign arm whose signed program had a step whose address
    data chose, each crossed with every injection task of its suite (AutoDojo's
    for banking, slack and travel; the official ones for workspace), as plan
    lines of at most nine cases: `<suite> <items>`."""
    from agentdojo.task_suite.load_suites import get_suite
    from savana_bench.agentdojo_tasks import BENCHMARK
    chosen = sorted({_task(r) for r in episodes(results, prefix) if r["data_chosen_steps"]},
                    key=lambda t: (SUITES.index(t[0]), int(t[1].rsplit("_", 1)[1])))
    lines = []
    for suite in SUITES:
        users = [u for s, u in chosen if s == suite]
        injections = sorted(get_suite(BENCHMARK, suite).injection_tasks, key=lambda i: int(i.rsplit("_", 1)[1]))
        items = [f"{u}+{i}" for u in users for i in injections]
        lines += [(suite, ",".join(items[k:k + 9])) for k in range(0, len(items), 9)]
    return lines


def report(results):
    arms = {arm: episodes(results, prefixes, SUPERSEDED.get(arm, ())) for arm, prefixes in ARMS.items()}
    out = dict(arms={arm: benign_summary(rows) for arm, rows in arms.items() if rows})
    out["flips"] = {f"{new}_vs_{old}": flips(arms[new], arms[old])
                    for new, old in (("U12", "G12"), ("U12", "D"), ("U8", "G12"), ("U8", "D"), ("U8", "U12"))
                    if arms[new] and arms[old]}
    attacked = episodes(results, ATTACK)
    if attacked:
        from analysis.night_reports import rows
        baseline = [*rows(results, "adojo")[0], *rows(results, "p0-matrix")[0]]
        out["attack"] = attack_summary(attacked, baseline)
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", default="results/local-container-20260930")
    parser.add_argument("what", nargs="?", default="report", choices=("report", "sample"))
    args = parser.parse_args()
    if args.what == "sample":
        for suite, items in attack_sample(args.results):
            print(suite, items)
    else:
        print(json.dumps(report(args.results), indent=1, sort_keys=True))
