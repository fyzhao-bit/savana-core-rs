"""Crash matrix over the executor's durable effect pipeline.

Reads the trial lines written by the kerneld test ``fused_crash_matrix_v04``
(``SAVANA_CRASH_MATRIX_OUT``) and groups them into rows. Each trial killed one
child process (SIGKILL) that ran one real fused dispatch; the parent reopened
the journal with the daemon's startup recovery, resent the kernel's original
dispatch, restarted once more, and counted provider requests.

A row is the kill point:

* ``before:n`` / ``after:n``: journal commit ``n`` is on disk, before or
  after its rollback anchor advanced;
* ``provider``: inside the provider, after it recorded the request (the
  external effect) and before the executor saw a response;
* ``random``: SIGKILL from the parent at a random time in the dispatch.

The bad states are fixed in the test, before any run: a second provider
request for the nonce, a resent dispatch or a restart that reaches the
provider again, an entry still in flight after recovery, an effect recorded as
a proven no-effect failure, a completion without an effect, an effect with no
journal entry, more than one entry, and a journal that cannot be reopened.

Usage, from ``experiments/``::

    python -m analysis.crash_matrix results/crash-matrix-20261011/*.jsonl
"""
import argparse
import collections
import json

# The four steps of the paper's journal-before-effect protocol, then the
# boundaries around them.
STEP = {
    "Prepared": "accepted, no attempt opened",
    "ProviderAttemptPrepared": "1. attempt record fsynced",
    "EffectStarted": "2. effect-started receipt stored",
    "EffectStarted+request": "3. first provider byte sent",
    "ProviderResponseRetained": "4. response encrypted and fsynced",
    "CompletionAvailable": "completion recorded",
    "Acknowledged": "kernel acknowledged",
    "-": "no executor entry yet",
}
ORDER = list(STEP)


def load(paths):
    trials = []
    for path in paths:
        with open(path) as handle:
            trials += [json.loads(line) for line in handle if line.strip()]
    return trials


def found(trial):
    """The journal state the crash left, split at the first provider byte."""
    state = trial["found"][0] if trial["found"] else "-"
    if state == "EffectStarted" and trial["effects"]["child"]:
        return "EffectStarted+request"
    return state


def kind(point):
    return point.split(":")[0] if point.startswith(("before", "after", "random")) else point


def rows(trials):
    """One row per journal state found at restart, over every kill kind."""
    table = collections.OrderedDict((state, collections.Counter()) for state in ORDER)
    finals = collections.defaultdict(collections.Counter)
    effects = collections.defaultdict(collections.Counter)
    bad = collections.defaultdict(collections.Counter)
    for trial in trials:
        if trial["point"] == "none":
            continue
        state = found(trial)
        table[state][kind(trial["point"])] += 1
        finals[state][trial["restarted"][0] if trial["restarted"] else "-"] += 1
        effects[state][sum(trial["effects"].values())] += 1
        for name in trial["bad"]:
            bad[state][name] += 1
    return [dict(state=state, step=STEP[state], kills=dict(kills), trials=sum(kills.values()),
                 final=dict(finals[state]), provider_requests=dict(effects[state]),
                 bad=dict(bad[state]))
            for state, kills in table.items() if kills]


def summary(trials):
    killed = [t for t in trials if t["point"] != "none"]
    return dict(
        trials=len(killed),
        killed=sum(t["exit"] == "killed" for t in killed),
        completed_before_kill=sum(t["exit"] == "completed" for t in killed),
        bad_trials=sum(bool(t["bad"]) for t in killed),
        max_provider_requests=max((sum(t["effects"].values()) for t in killed), default=0),
        reissued_after_crash=sum(t["effects"]["replay"] + t["effects"]["restart"] for t in killed
                                 if t["found"]),
    )


def markdown(table):
    lines = ["| Journal state at restart | Step | Trials (kill kind) | State after recovery "
             "| Provider requests | Bad |", "|---|---|---|---|---|---|"]
    for row in table:
        kills = ", ".join(f"{k} {n}" for k, n in sorted(row["kills"].items()))
        final = ", ".join(f"{k} {n}" for k, n in sorted(row["final"].items()))
        requests = ", ".join(f"{k}: {n}" for k, n in sorted(row["provider_requests"].items()))
        bad = sum(row["bad"].values())
        lines.append(f"| {row['state']} | {row['step']} | {row['trials']} ({kills}) | {final} "
                     f"| {requests} | {bad} |")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args()
    trials = load(args.paths)
    print(markdown(rows(trials)))
    print(json.dumps(summary(trials), indent=2))


if __name__ == "__main__":
    main()
