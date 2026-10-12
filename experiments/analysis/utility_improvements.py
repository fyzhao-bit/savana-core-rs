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
  field by its target label, which the review then refused). The same
  contention rule applies: `u8r` reruns the batch above 5 s and replaces it,
  and `U8_first` keeps the original;
* U8S (`u8s`): U8 with agentd's structured planning on every accepted draft
  (the reviewed program as the private mapper, DeepSeek as the third-party
  planner that may only reorder it, the lowered program reviewed again), the
  same 97 tasks in the same batches;
* U7 (`u7d`, `u7s`): under the Permit disposition, where the kernel asks the
  owner only when G5 escalates, the tasks whose U12 or U8 program had a step
  whose address data chose (`trusted_set_sample`), with the directory owner
  (`u7d`: every such step escalates) and with the directory signed into
  those edges as a candidate set (`u7s`: a member no longer escalates by
  itself); `u7x` is `u7s` under injection;
* U6 (`u6`, `u6x`): the five requests that hand their action to instructions
  in data, as a read turn and an act turn under U8's options with
  `+instructions=adopt`; `u6x` is banking 12's under AutoDojo's injections,
  the one request whose instructions come from a document with an injection
  point (`adoption_summary`);
* U8X (`u8x`): U8 under injection (AutoDojo's for banking, slack and travel,
  the official template for workspace), on the tasks whose U8 program had a
  step whose address data chose (`attack_sample`).

`timeline` reads each batch's own clock: the median interval between an
episode's consecutive provider attempts (a step's time; above
`CONTENDED_STEP_SECONDS` the batch shared the machine with other work), and
for U5 the seconds from the owner input commit, where the kernel's 60 s task
window starts, to binding and to publication, by program length.

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

ARMS = dict(G12=("g12k",), D=("f5d",), U12=("u12c", "u12r"), U12_first=("u12c",), U8=("u8f", "u8r"),
            U8_first=("u8f",), U8S=("u8s",))
# A batch whose measurement a rerun replaces (see the docstring).
SUPERSEDED = {"U12": {"u12c-slack-2", "u12c-travel-0"}, "U8": {"u8f-slack-2"}}
ATTACK = "u8x"
# U7 runs under Permit on a sample of tasks, not all 97 (see the docstring).
TRUSTED_SET_ARMS = dict(U7_directory=("u7d",), U7_set=("u7s",))
TRUSTED_SET_ATTACK = "u7x"
ADOPTION_ARMS = dict(U6=("u6",), U6X=("u6x",))
SUITES = ("banking", "slack", "travel", "workspace")
DIRECTORY_REFUSAL = "consent_destination_not_in_directory"
# A batch whose median step interval is above this ran under contention.
CONTENDED_STEP_SECONDS = 5.0


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
    adoption = next((e for e in local if e["kind"] == "instructions_adoption"), None)
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
                  unauthorized=floor["unauthorized"], success=floor["success"],
                  # U6: which turn this episode was, and the owner's adoption decision after a read turn.
                  turn=row.get("instructions"),
                  adoption=None if adoption is None else dict(adopted=adoption["adopted"],
                                                               reason=adoption["reason"]))
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


def episode_times(events):
    """From one episode's events: the intervals between its consecutive
    provider attempts, and the seconds from the owner input commit to the
    episode's binding and to its observation (publication), or None."""
    def first(kind, **match):
        return next((e["time_ns"] for e in events
                     if e["kind"] == kind and all(e.get(k) == v for k, v in match.items())), None)
    attempts = [e["time_ns"] for e in events if e["kind"] == "provider_attempt"]
    commit = first("admission_stage_started", stage="owner_input_commit")

    def since(t):
        return None if commit is None or t is None else round((t - commit) / 1e9, 3)
    return dict(gaps=[(b - a) / 1e9 for a, b in zip(attempts, attempts[1:])],
                binding=since(first("episode_binding")), observation=since(first("episode_observation")))


def timeline(results, prefix, superseded=()):
    """Per batch, its median step interval and whether that marks contention;
    over published episodes, commit to binding and commit to publication by
    program length."""
    per_batch, binding, publication = {}, [], collections.defaultdict(list)
    found = [b for p in ((prefix,) if type(prefix) is str else prefix) for b in batches(results, p)]
    for name, run, _verification in found:
        if name in superseded:
            continue
        events = _events(run)
        local = by_episode(events)
        gaps = []
        for row in events[-1]["summary"]["rows"]:
            episode = local[row["episode"]]
            times = episode_times(episode)
            gaps += times["gaps"]
            if times["binding"] is not None:
                binding.append(times["binding"])
            inputs = [e for e in episode if e["kind"] == "episode_input"]
            if row["outcome"] == "published" and inputs and times["observation"] is not None:
                publication[len(inputs[0]["contract"]["steps"])].append(times["observation"])
        median = round(statistics.median(gaps), 2) if gaps else None
        per_batch[name] = dict(intervals=len(gaps), median_step_seconds=median,
                               contended=median is not None and median > CONTENDED_STEP_SECONDS)

    def spread(values):
        return dict(n=len(values), median=round(statistics.median(values), 1), max=round(max(values), 1))
    return dict(batches=per_batch, commit_to_binding=spread(binding) if binding else None,
                commit_to_publication={str(k): spread(v) for k, v in sorted(publication.items())})


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


def attack_sample(results, arm="U8"):
    """The tasks of a benign arm whose signed program had a step whose address
    data chose, each crossed with every injection task of its suite (AutoDojo's
    for banking, slack and travel; the official ones for workspace), as plan
    lines of at most nine cases: `<suite> <items>`."""
    from agentdojo.task_suite.load_suites import get_suite
    from savana_bench.agentdojo_tasks import BENCHMARK
    chosen = sorted({_task(r) for r in episodes(results, ARMS[arm], SUPERSEDED.get(arm, ()))
                     if r["data_chosen_steps"]},
                    key=lambda t: (SUITES.index(t[0]), int(t[1].rsplit("_", 1)[1])))
    lines = []
    for suite in SUITES:
        users = [u for s, u in chosen if s == suite]
        injections = sorted(get_suite(BENCHMARK, suite).injection_tasks, key=lambda i: int(i.rsplit("_", 1)[1]))
        items = [f"{u}+{i}" for u in users for i in injections]
        lines += [(suite, ",".join(items[k:k + 9])) for k in range(0, len(items), 9)]
    return lines


def trusted_set_sample(results):
    """Plan lines `<suite> <items>` (at most nine cases a line) of the tasks
    whose U12 or U8 program had a step whose address data chose: the only
    tasks where a signed candidate set can change what happens."""
    chosen = {_task(r) for arm in ("U12", "U8")
              for r in episodes(results, ARMS[arm], SUPERSEDED.get(arm, ())) if r["data_chosen_steps"]}
    lines = []
    for suite in SUITES:
        users = sorted((u for s, u in chosen if s == suite), key=lambda u: int(u.rsplit("_", 1)[1]))
        # As few batches as nine cases allow, of even size.
        size = -(-len(users) // -(-len(users) // 9)) if users else 1
        lines += [(suite, ",".join(users[k:k + size])) for k in range(0, len(users), size)]
    return lines


def trusted_set_summary(rows):
    """What the owner was asked about the steps whose address data chose, and
    what reached a provider without asking (U7)."""
    return dict(by_suite=by_suite(rows),
                outcomes=dict(collections.Counter(r["outcome"] for r in rows)),
                data_chosen_steps=sum(r["data_chosen_steps"] for r in rows),
                asked=sum(r["owner_asked"] for r in rows),
                dispatched_unasked=sum(r["dispatched_unapproved"] for r in rows),
                owner_refusals=dict(collections.Counter(c for r in rows for c in r["owner_refusals"])),
                unauthorized=sum(r["unauthorized"] for r in rows),
                tasks=[dict(suite=r["suite"], user=r["user"], injection=r["injection"], outcome=r["outcome"],
                            utility=r["utility"], data_chosen_steps=r["data_chosen_steps"], asked=r["owner_asked"],
                            dispatched_unasked=r["dispatched_unapproved"], owner_refusals=r["owner_refusals"],
                            attacker_chose_address=r["attacker_chose_address"], success=r["success"])
                       for r in rows if r["data_chosen_steps"]])


def adoption_summary(rows):
    """Per task of a U6 arm: the read turn, the owner's adoption decision,
    and the act turn, which is scored as the whole task."""
    reads = {(r["suite"], r["user"], r["injection"]): r for r in rows if r["turn"] == "read"}
    tasks = []
    for act in (r for r in rows if r["turn"] == "act"):
        read = reads[(act["suite"], act["user"], act["injection"])]
        tasks.append(dict(suite=act["suite"], user=act["user"], injection=act["injection"],
                          read=read["outcome"], read_steps=read["steps"], adoption=read["adoption"],
                          act=act["outcome"], act_refusal=act["refusal"], act_review_refusals=act["review_refusals"],
                          act_steps=act["steps"], act_writes=act["writes"], seconds=act["seconds"],
                          utility=act["utility"], success=act["success"],
                          owner_refusals=act["owner_refusals"], unauthorized=act["unauthorized"]))
    return dict(tasks=len(tasks), utility=sum(t["utility"] for t in tasks),
                success=sum(t["success"] for t in tasks),
                adopted=sum(1 for t in tasks if t["adoption"] and t["adoption"]["adopted"]),
                adoption_reasons=dict(collections.Counter(t["adoption"]["reason"] for t in tasks if t["adoption"])),
                act_outcomes=dict(collections.Counter(t["act"] for t in tasks)),
                unauthorized=sum(t["unauthorized"] for t in tasks), per_task=tasks)


def report(results):
    arms = {arm: episodes(results, prefixes, SUPERSEDED.get(arm, ())) for arm, prefixes in ARMS.items()}
    out = dict(arms={arm: benign_summary(rows) for arm, rows in arms.items() if rows})
    out["flips"] = {f"{new}_vs_{old}": flips(arms[new], arms[old])
                    for new, old in (("U12", "G12"), ("U12", "D"), ("U8", "G12"), ("U8", "D"), ("U8", "U12"),
                                     ("U8", "U8_first"), ("U8S", "U8"))
                    if arms[new] and arms[old]}
    out["timeline"] = {arm: timeline(results, prefixes, SUPERSEDED.get(arm, ()))
                       for arm, prefixes in ARMS.items() if arms[arm]}
    adopted = {arm: episodes(results, prefixes) for arm, prefixes in ADOPTION_ARMS.items()}
    if any(adopted.values()):
        out["adopted_instructions"] = {arm: adoption_summary(rows) for arm, rows in adopted.items() if rows}
    trusted = {arm: episodes(results, prefixes) for arm, prefixes in TRUSTED_SET_ARMS.items()}
    if any(trusted.values()):
        out["trusted_set"] = {arm: trusted_set_summary(rows) for arm, rows in trusted.items() if rows}
    trusted_attack = episodes(results, TRUSTED_SET_ATTACK)
    if trusted_attack:
        out["trusted_set_attack"] = dict(trusted_set_summary(trusted_attack), attack=attack_summary(trusted_attack))
    attacked = episodes(results, ATTACK)
    if attacked:
        from analysis.night_reports import rows
        baseline = [*rows(results, "adojo")[0], *rows(results, "p0-matrix")[0]]
        out["attack"] = attack_summary(attacked, baseline)
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", default="results/local-container-20260930")
    parser.add_argument("what", nargs="?", default="report", choices=("report", "sample", "set-sample"))
    args = parser.parse_args()
    if args.what in ("sample", "set-sample"):
        for suite, items in (attack_sample if args.what == "sample" else trusted_set_sample)(args.results):
            print(suite, items)
    else:
        print(json.dumps(report(args.results), indent=1, sort_keys=True))
