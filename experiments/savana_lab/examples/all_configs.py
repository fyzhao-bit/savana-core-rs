#!/usr/bin/env python3
"""Every configuration of the U9 experiments, in one script.

U9 (`sl.U9`) is the base; every other configuration is U9 with one or two options changed:

  benign tasks, for utility
    u9                    the base configuration
    u9h                   the upper bound: an owner who approves every destination it is shown
    pro                   a stronger planner model (deepseek-v4-pro)
    mask                  privacy masking for the planner and the extractor (view=masked, extract=masked)
    mask-planner          masking for the planner only
    mask-extractor        masking for the extractor only
  attack pairs (user task + injection task), for security
    attack                AgentDojo's own injections (important_instructions), all four suites
    autodojo              AutoDojo's optimized injections (banking, slack, travel)
    exposure              AutoDojo's injections, and the planner is also shown the injected data
  a compromised planner (benign environments)
    poison-<goal>         a hidden attacker goal in the planner's prompt: exfiltrate, redirect, tamper, obey_data
  a polluted private mapper (structured planning drafts inside agentd's mapper call, mapper=service)
    mapper-honest         no pollution: what planning inside the mapper call costs
    mapper-poison-<goal>  the mapper with a hidden goal
    mapper-exposure       the mapper shown AutoDojo's injected data

Run it from the repository root, in the lab venv, after `setup` and `artifacts build`
(savana_lab/README.zh-CN.md), with $DEEPSEEK_API_KEY set:

    python experiments/savana_lab/examples/all_configs.py                    # list: spec, tasks, batches
    python experiments/savana_lab/examples/all_configs.py --smoke            # the same, two banking tasks each
    python experiments/savana_lab/examples/all_configs.py --quick mask       # one task here, no host: NOT evidence
    python experiments/savana_lab/examples/all_configs.py --run u9 mask      # run these, one after the other
    python experiments/savana_lab/examples/all_configs.py --run all --smoke  # every configuration, one batch each

A run is named `<prefix>-<configuration>` (prefix `cfg`, or `smoke` with --smoke). Running a name
again resumes it: its verified batches are skipped. A machine runs one driver at a time, so --run goes
through the configurations in order, in the foreground (use nohup or tmux for long runs), and stops
at a run that fails; `python -m savana_lab stop` from another shell stops it after the running batch.
Each batch's host is a Docker container here, or a new machine with the same --host options as
`python -m savana_lab run` (--host ssh ..., --host aws ...). Every result counts only once the
offline verifier has passed its batch, as for any savana_lab run.

A run stages a commit, so a configuration changed here runs only once it is committed; or copy
this file out of the repository and run it with PYTHONPATH=<repository>/experiments.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))   # experiments/

import savana_lab as sl  # noqa: E402
from savana_bench.autodojo_cache import SUITES as AUTODOJO_SUITES  # noqa: E402
from savana_bench.root_drafter import ROOT_POISON_GOALS  # noqa: E402
from savana_lab.__main__ import _hosts, _hosts_options  # noqa: E402  (the CLI's --host options)
from savana_lab.artifacts import ArtifactError  # noqa: E402
from savana_lab.driver import LabError  # noqa: E402
from savana_lab.host import HostError  # noqa: E402
from savana_lab.plan import USER_TASKS  # noqa: E402

# AgentDojo v1.2.2's injection tasks per suite; slack's are numbered from 1.
INJECTION_TASKS = dict(banking=range(9), slack=range(1, 6), travel=range(7), workspace=range(14))

BENIGN, PAIRS, AUTODOJO = "benign tasks", "attack pairs", "AutoDojo pairs"


@dataclass(frozen=True)
class Arm:
    name: str
    config: sl.Config
    tasks: str       # BENIGN, PAIRS or AUTODOJO
    measures: str


def arms():
    """Every configuration, in the order `--run all` goes."""
    mapper = replace(sl.U9, mapper="service")
    found = [
        Arm("u9", sl.U9, BENIGN, "utility of the base configuration"),
        Arm("u9h", sl.U9H, BENIGN, "utility with an owner who approves every destination it is shown"),
        Arm("pro", replace(sl.U9, planner="deepseek-v4-pro"), BENIGN, "utility with a stronger planner model"),
        Arm("mask", sl.U9.masked(), BENIGN, "utility with masking for the planner and the extractor"),
        Arm("mask-planner", sl.U9.masked(extractor=False), BENIGN, "utility with masking for the planner only"),
        Arm("mask-extractor", sl.U9.masked(planner=False), BENIGN, "utility with masking for the extractor only"),
        Arm("attack", sl.U9, PAIRS, "security against AgentDojo's own injections"),
        Arm("autodojo", replace(sl.U9, attack="autodojo"), AUTODOJO, "security against AutoDojo's injections"),
        Arm("exposure", replace(sl.U9, attack="autodojo", exposure="data"), AUTODOJO,
            "security when the planner also sees the injected data"),
    ]
    found += [Arm(f"poison-{goal}", replace(sl.U9, goal=goal), BENIGN, f"a compromised planner (goal {goal})")
              for goal in ROOT_POISON_GOALS]
    found.append(Arm("mapper-honest", mapper, BENIGN, "utility when the private mapper plans"))
    found += [Arm(f"mapper-poison-{goal}", replace(mapper, goal=goal), BENIGN, f"a polluted mapper (goal {goal})")
              for goal in ROOT_POISON_GOALS]
    found.append(Arm("mapper-exposure", replace(mapper, attack="autodojo", exposure="data"), AUTODOJO,
                     "a polluted mapper: it sees AutoDojo's injected data"))
    return found


def tasks(kind, suites, per_suite=None):
    """The (suite, item) list of one kind over `suites`, at most `per_suite` of each."""
    out = []
    for suite in suites:
        if kind == BENIGN:
            items = sl.benign(suite)
        elif kind == AUTODOJO and suite not in AUTODOJO_SUITES:
            continue   # AutoDojo has no injections for this suite
        else:
            items = sl.pairs(suite, range(USER_TASKS[suite]), INJECTION_TASKS[suite])
        out += items[:per_suite]
    return out


def plans(chosen, prefix, suites, per_suite):
    """[(Arm, Plan or None)]: None where these suites hold none of its tasks."""
    out = []
    for arm in chosen:
        task_list = tasks(arm.tasks, suites, per_suite)
        out.append((arm, sl.make_plan(f"{prefix}-{arm.name}", arm.config, task_list) if task_list else None))
    return out


def show(planned, prefix):
    total = 0
    for arm, plan in planned:
        print(f"{prefix}-{arm.name}: {arm.measures}")
        print(f"  {arm.config.template()}")
        if plan is None:
            print(f"  no {arm.tasks} in these suites")
            continue
        total += len(plan.batches)
        print(f"  {len(plan.tasks())} {arm.tasks}, {len(plan.batches)} batches")
    print(f"{total} batches in all; each runs on a brand-new host")


def summary(lab, name):
    """Utility, and for attack pairs AgentDojo's security verdicts, of a run's verified batches."""
    report = lab.report(name)
    rows = report.rows()
    lines = [str(report.utility())]
    attacked = [r for r in rows if r.get("injection")]
    if attacked:
        hits = sum(r.get("attacker_success") is True for r in attacked)
        unscored = sum(r.get("attacker_success") is None for r in attacked)
        lines.append(f"  attacker success (AgentDojo's security oracle): {hits}/{len(attacked)} pairs, "
                     f"{unscored} not scored")
    lines.append(f"  unauthorized provider attempts: {sum(r.get('unauthorized_provider_attempts') or 0 for r in rows)}")
    return "\n".join(lines)


def run_all(lab, planned, host=None):
    """Run each plan to its end, one after the other; stop at the first that does not finish.
    `host`: where each batch's brand-new host comes from (None: a Docker container here)."""
    lab.echo = True
    for arm, plan in planned:
        if plan is None:
            print(f"skip {arm.name}: no {arm.tasks} in these suites")
            continue
        print(f"\n== {plan.name}: {arm.measures}", flush=True)
        handle = lab.create(plan, host=host)
        result = handle.start()
        print(handle.status())
        print(summary(lab, plan.name))
        if result != "done":
            print(f"{plan.name} {result}: run the same command again to resume it")
            return 2
    return 0


def analysis_hint(lab, prefix):
    """How to read whether a hidden goal or the injected data got anywhere (drafts, calls, effects)."""
    p = prefix
    return ("\nWhether a planner's or a mapper's pollution got into a draft, a call or an effect, "
            "from experiments/:\n"
            f"    python -m analysis.polluted_mapper --results {lab.results} \\\n"
            f"        --goal-prefix {p}-mapper-poison --data-prefix {p}-mapper-exposure "
            f"--honest-prefix {p}-mapper-honest \\\n"
            f"        --baseline-goal-prefix {p}-poison --baseline-data-prefix {p}-exposure "
            f"--baseline-honest-prefix {p}-u9")


def quick(arm, suites, task, model_calls):
    """One task of `arm` in this process: no host, no kernel, NOT experiment evidence."""
    if task:
        suite, _, item = task.partition(":")
    else:
        candidates = tasks(arm.tasks, suites, 1)
        if not candidates:
            raise LookupError(f"no {arm.tasks} for {arm.name} in these suites")
        suite, item = candidates[0]
    result = sl.quick(arm.config, suite, item)
    print(result)
    for call in result.model_calls() if model_calls else ():
        print(f"\n[{' '.join(f'{k}={v}' for k, v in call.items() if k not in ('shown', 'reply'))}]")
        if "shown" in call:
            print("shown:", call["shown"])
        print("reply:", call["reply"])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--run", nargs="+", metavar="NAME", help="run these configurations, or: all")
    action.add_argument("--quick", metavar="NAME", help="try one task of this configuration here: NOT evidence")
    parser.add_argument("--task", metavar="SUITE:ITEM", help="the task --quick tries (default: the first)")
    parser.add_argument("--model-calls", action="store_true", help="with --quick: what each model saw and said")
    parser.add_argument("--smoke", action="store_true", help="two banking tasks per configuration, one batch each")
    parser.add_argument("--suites", help="comma-separated suites (default: all four; AutoDojo has no workspace)")
    parser.add_argument("--per-suite", type=int, help="at most this many tasks of each suite")
    parser.add_argument("--prefix", help="runs are named <prefix>-<configuration> (default: cfg, or smoke)")
    _hosts_options(parser)
    args = parser.parse_args(argv)

    suites = args.suites.split(",") if args.suites else ["banking"] if args.smoke else list(sl.SUITES)
    per_suite = args.per_suite if args.per_suite is not None else 2 if args.smoke else None
    prefix = args.prefix or ("smoke" if args.smoke else "cfg")
    by_name = {arm.name: arm for arm in arms()}
    wanted = args.run or ([args.quick] if args.quick else [])
    unknown = [n for n in wanted if n not in by_name and n != "all"]
    if unknown:
        parser.error(f"unknown configuration {', '.join(unknown)}; one of: all, {', '.join(by_name)}")
    if any(suite not in sl.SUITES for suite in suites):
        parser.error(f"--suites takes {', '.join(sl.SUITES)}")
    if per_suite is not None and per_suite < 1:
        parser.error("--per-suite takes a number from 1")
    try:
        if args.quick:
            quick(by_name[args.quick], suites, args.task, args.model_calls)
            return 0
        chosen = list(by_name.values()) if not args.run or "all" in args.run else [by_name[n] for n in args.run]
        planned = plans(chosen, prefix, suites, per_suite)
        if not args.run:
            show(planned, prefix)
            return 0
        lab = sl.Lab()
        code = run_all(lab, planned, _hosts(args))
        if any(arm.name.startswith(("poison-", "mapper-", "exposure")) for arm in chosen):
            print(analysis_hint(lab, prefix))
        return code
    except (LabError, sl.ConfigError, ArtifactError, HostError, LookupError) as error:
        print(f"all_configs: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
