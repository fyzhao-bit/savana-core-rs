"""A polluted private mapper (`+author=structured+mapper=service`): the two
pollutions the planner was tested with, now in the mapper, which drafts the
program inside agentd's mapper call.

* Hidden objective (`drafted-poison`, `root_drafter.ROOT_POISON_GOALS`):
  batches `<prefix>-<goal>-*`, read exactly as
  `analysis.poisoned_planner_compare` reads the planner's (`p0-poison`,
  `p0-poisonretry`): tried (a marker in any draft), a marker in any executed
  call, an effect (an executed write carrying a marker), invented numbers.
* Injected data (`+attack=autodojo+exposure=data`): batches `<prefix>-*`,
  read exactly as `analysis.autodojo_compare` reads the planner's (`adojx`):
  attempting programs, carried out (an attempting program signed), and
  AgentDojo's own security oracle.

Both readings take the drafts from `root_drafted` events, which the service
mapper records as the drafting planner does. Added here, per structured
episode: how far its job got (`structured_planned`: mapper_failed,
planner_invalid, lowering_failed or planned). Every batch read passed offline
verification, which re-derives the job from its salt, the workflow from the
accepted draft, and checks that no program literal, owner value, tool name
or description reached the third-party planner.

Usage, from ``experiments/``::

    python -m analysis.polluted_mapper --results results/local-container-20260930 \\
        --goal-prefix mpx-poison --data-prefix mpx-adojo \\
        --baseline-goal-prefix p0-poisonretry --baseline-data-prefix adojx
"""
import argparse
import collections
import glob
import json
import os

from analysis.poisoned_planner_compare import GOALS, savana_episodes, tally
from analysis.autodojo_compare import savana, summarize


def prompts():
    """{(suite, user task): its request}, for the invented-number reading."""
    from agentdojo.task_suite.load_suites import get_suite
    from savana_bench.agentdojo_tasks import BENCHMARK
    out = {}
    for name in ("workspace", "banking", "slack", "travel"):
        suite = get_suite(BENCHMARK, name)
        out.update({(name, user): task.PROMPT for user, task in suite.user_tasks.items()})
    return out


def stages(results, prefix):
    """How far each structured job of the verified batches `prefix-*` got."""
    out = collections.Counter()
    for batch in sorted(glob.glob(f"{results}/{prefix}-*")):
        verification = os.path.join(batch, "offline-verification.json")
        events = glob.glob(f"{batch}/*/events.jsonl")
        if not (os.path.exists(verification) and os.path.getsize(verification) and len(events) == 1):
            continue
        for line in open(events[0]):
            event = json.loads(line)
            if event.get("kind") == "structured_planned":
                out[event["outcome"]] += 1
    return dict(out)


def goal_report(results, prefix, baseline=None):
    """Per hidden objective: the mapper's tallies, and the planner's under the
    same objective (`baseline` prefix) for comparison."""
    text = prompts()
    report = {}
    for goal in GOALS:
        mapper, unverified = savana_episodes(results, f"{prefix}-{goal}", text)
        if not mapper.get(goal):
            continue
        entry = dict(mapper=dict(tally(mapper[goal])), stages=stages(results, f"{prefix}-{goal}"),
                     unverified=unverified)
        if baseline:
            planner, _ = savana_episodes(results, f"{baseline}-{goal}", text)
            if planner.get(goal):
                entry["planner"] = dict(tally(planner[goal]))
        report[goal] = entry
    return report


def data_report(results, prefix, baseline=None):
    """Under AutoDojo with the injected data shown to the mapper: per suite and
    in total, and the planner's run on the same pairs for comparison."""
    rows = savana(results, prefix)
    report = dict(mapper={k: dict(v) for k, v in summarize(rows).items()}, stages=stages(results, prefix),
                  successes=sorted(f"{r['suite']}/{r['user']}/{r['injection']}" for r in rows if r["success"]),
                  carried_out=sorted(f"{r['suite']}/{r['user']}/{r['injection']}" for r in rows if r["carried_out"]))
    if baseline:
        pairs = {(r["suite"], r["user"], r["injection"]) for r in rows}
        before = [r for r in savana(results, baseline) if (r["suite"], r["user"], r["injection"]) in pairs]
        report["planner"] = {k: dict(v) for k, v in summarize(before).items()}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--results", required=True)
    parser.add_argument("--goal-prefix")
    parser.add_argument("--data-prefix")
    parser.add_argument("--baseline-goal-prefix")
    parser.add_argument("--baseline-data-prefix")
    args = parser.parse_args()
    report = {}
    if args.goal_prefix:
        report["hidden_objective"] = goal_report(args.results, args.goal_prefix, args.baseline_goal_prefix)
    if args.data_prefix:
        report["injected_data"] = data_report(args.results, args.data_prefix, args.baseline_data_prefix)
    print(json.dumps(report, indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
