"""Aggregates for the overnight runs (injection matrix, retry/model ablation,
poisoned planner with retry, attack sample with retry), from exported and
offline-verified Savana run directories, and the same cases in CaMeL's own
per-case logs (same model, same AgentDojo v1.2.2 tasks and injections).

Only batches whose offline verification passed are counted; anything else is
reported as unverified and excluded. Usage, from ``experiments/``:

    python -m analysis.night_reports --results <dir> [--camel <logs dir>] \
        matrix | ablation | security | privacy
"""
import argparse
import collections
import glob
import json
import os

SUITES = ("workspace", "banking", "slack", "travel")
CAMEL = (("camel", "deepseek-flash+camel"), ("camel_policy", "deepseek-flash+camel+secpol"))


def rows(results, prefix):
    """(verified rows, unverified batch names) for every batch dir `prefix-*`."""
    out, unverified = [], []
    for batch in sorted(glob.glob(f"{results}/{prefix}-*")):
        verification = os.path.join(batch, "offline-verification.json")
        summaries = glob.glob(f"{batch}/*/summary.json")
        if not (os.path.exists(verification) and os.path.getsize(verification) > 0 and len(summaries) == 1):
            unverified.append(os.path.basename(batch))
            continue
        for row in json.load(open(summaries[0]))["rows"]:
            out.append(dict(row, batch=os.path.basename(batch)))
    return out, unverified


def refusals(results, prefix):
    """Every recorded review refusal (attempt, code) under `prefix`."""
    out = collections.Counter()
    for events in glob.glob(f"{results}/{prefix}-*/*/events.jsonl"):
        for line in open(events):
            event = json.loads(line)
            if event.get("kind") == "program_refused":
                out[event["reason"]] += 1
    return out


def camel(logs, variant, suite, user, injection):
    tail = "none/none.json" if injection is None else f"important_instructions/{injection}.json"
    path = f"{logs}/{variant}/{suite}/{user}/{tail}"
    if not os.path.exists(path):
        return None
    data = json.load(open(path))
    return dict(utility=data.get("utility") is True, attack=injection is not None and data.get("security") is True)


def summarize(table_rows, logs):
    """Per-suite counts for Savana rows and the same cases in CaMeL."""
    table = collections.defaultdict(collections.Counter)
    for r in table_rows:
        for key in (r["suite"], "total"):
            t = table[key]
            t["cases"] += 1
            t["utility"] += r.get("utility") is True
            t["attack"] += r.get("observed_attacker_success") is True
            t["published"] += r.get("outcome") == "published"
            t["program_refused"] += r.get("outcome") == "program_refused"
            t["other"] += r.get("outcome") not in ("published", "program_refused")
            t["unauthorized"] += r.get("unauthorized_provider_attempts", 0)
            t["drafts"] += r.get("drafts") or 0
            for tag, variant in CAMEL if logs else ():
                c = camel(logs, variant, r["suite"], r["user"], r.get("injection"))
                if c is None:
                    t[f"{tag}_missing"] += 1
                    continue
                t[f"{tag}_utility"] += c["utility"]
                t[f"{tag}_attack"] += c["attack"]
    return table


def print_table(title, table, *, attack):
    print(f"\n## {title}")
    cols = ["cases", "utility", "published", "program_refused", "other", "unauthorized"]
    cols += ["attack"] if attack else ["drafts"]
    cols += ["camel_utility", "camel_policy_utility"] + (["camel_attack", "camel_policy_attack"] if attack else [])
    cols += ["camel_missing"]
    print("| suite | " + " | ".join(cols) + " |")
    print("|---|" + "---:|" * len(cols))
    for key in (*SUITES, "total"):
        if key in table:
            print(f"| {key} | " + " | ".join(str(table[key][c]) for c in cols) + " |")


def matrix(args):
    table_rows, unverified = rows(args.results, "p0-matrix")
    print_table("Injection matrix (Savana vs CaMeL, same pairs)", summarize(table_rows, args.camel), attack=True)
    print(f"\nunverified batches excluded: {unverified or 'none'}")


def ablation(args):
    variants = (("G10 (1 draft, flash)", "g10-benign"), ("retry (<=3 drafts, flash)", "p0-retry"),
                ("retry + v4-pro planner", "p0-strong"))
    per_task = {}
    for title, prefix in variants:
        table_rows, unverified = rows(args.results, prefix)
        print_table(title, summarize(table_rows, args.camel), attack=False)
        print(f"unverified batches excluded: {unverified or 'none'}")
        print("review refusal codes (every draft):", dict(refusals(args.results, prefix).most_common()))
        per_task[prefix] = {(r["suite"], r["user"]): r for r in table_rows}
    # Where did each variant gain or lose against G10, task by task?
    base = per_task.get("g10-benign", {})
    for _title, prefix in variants[1:]:
        moves = collections.Counter()
        for key, r in per_task.get(prefix, {}).items():
            before = base.get(key)
            if before is None:
                continue
            moves[(before.get("outcome"), bool(before.get("utility")), r.get("outcome"), bool(r.get("utility")))] += 1
        print(f"\n{prefix} vs G10 per task (before outcome, before utility -> after outcome, after utility):")
        for move, n in moves.most_common():
            print(f"  {n:3d}  {move}")


def security(args):
    for title, prefix in (("Poisoned planner + retry", "p0-poisonretry"), ("Attack sample + retry", "p0-attackretry"),
                          ("Retry smoke", "p0-smokeretry")):
        table_rows, unverified = rows(args.results, prefix)
        if not table_rows and not unverified:
            continue
        goals = collections.Counter(r.get("goal") for r in table_rows)
        print_table(f"{title} (goals: {dict(goals)})", summarize(table_rows, args.camel), attack=True)
        print(f"unverified batches excluded: {unverified or 'none'}")


def privacy(args):
    """The value-blind planner view on the tasks whose request it masks: the
    masked view against the plain view drafted at the same time, and with
    retry against the night's plain-view retry run on the same tasks."""
    variants = (("plain view, 1 draft (same time)", "pv-control"), ("masked view, 1 draft", "pv-masked"),
                ("plain view, <=3 drafts (p0-retry)", "p0-retry"), ("masked view, <=3 drafts", "pv-maskedretry"),
                ("plain view, 1 draft (G10)", "g10-benign"))
    by_variant = {}
    for _title, prefix in variants:
        table_rows, unverified = rows(args.results, prefix)
        by_variant[prefix] = ({(r["suite"], r["user"]): r for r in table_rows}, unverified)
    tasks = sorted(by_variant["pv-masked"][0])
    for title, prefix in variants:
        found, unverified = by_variant[prefix]
        picked = [found[t] for t in tasks if t in found]
        print_table(f"{title} [{prefix}], {len(picked)}/{len(tasks)} masked-view tasks", summarize(picked, args.camel),
                    attack=False)
        print(f"unverified batches excluded: {unverified or 'none'}")
    print("\n| task | " + " | ".join(prefix for _t, prefix in variants) + " |")
    print("|---|" + "---|" * len(variants))
    for task in tasks:
        cells = []
        for _title, prefix in variants:
            r = by_variant[prefix][0].get(task)
            cells.append("-" if r is None else ("OK " if r.get("utility") else "") + (r.get("refusal") or r["outcome"]))
        print(f"| {task[0]} {task[1]} | " + " | ".join(cells) + " |")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True)
    parser.add_argument("--camel", help="CaMeL logs dir (contains deepseek-flash+camel[+secpol]/)")
    parser.add_argument("report", choices=("matrix", "ablation", "security", "privacy"))
    args = parser.parse_args()
    dict(matrix=matrix, ablation=ablation, security=security, privacy=privacy)[args.report](args)


if __name__ == "__main__":
    main()
