"""Exhaustive BFS of each finite product graph; fail closed on truncation.

Run from repository root: python3 -m verification.task_trace.check
The JSON output is generated research evidence, never a production policy input.
"""

import argparse
import hashlib
import json
from collections import Counter, deque
from dataclasses import asdict
from pathlib import Path

from . import model, spec
from .domain import ACTIONS, MUTANTS, SCENARIOS, Event, Scenario


def observe(scenario: Scenario, audit: spec.Audit, state: model.State) -> None:
    spec.check_projection(
        scenario,
        audit,
        attempts=state.attempts,
        magnitude=state.magnitude,
        root=state.root,
        version=state.version,
        epoch=state.epoch,
        revoked=state.revoked,
        statuses=tuple(r.status for r in state.requests),
    )


def event_json(event: Event) -> dict:
    output = {
        key: value for key, value in asdict(event).items() if value not in (-1, "")
    }
    if event.action >= 0:
        output["request_tuple"] = asdict(ACTIONS[event.action])
    return output


def coverage(scenario: Scenario, state: model.State, event: Event) -> set[str]:
    found = {event.kind + (":" + event.outcome if event.outcome else "")}
    if event.kind == "reserve":
        clause = scenario.slots[event.request]
        if scenario.contracts[state.root].predecessors[clause]:
            found.add("dependent_successor_admitted")
        if any(
            scenario.slots[j] == clause and r.status == "no_effect"
            for j, r in enumerate(state.requests)
        ):
            found.add("retry_after_proven_no_effect")
    if event.kind == "emit" and state.revoked:
        found.add("already_reserved_attempt_after_revocation")
    if (
        event.kind == "settle"
        and event.outcome == "success"
        and state.requests[event.request].status == "prepared"
    ):
        found.add("terminal_first_success")
    if event.kind == "executor_reopen" and any(
        r.executor in ("retained", "success") for r in state.requests
    ):
        found.add("retained_success_survives_executor_reopen")
    if event.kind == "amend" and any(state.attempts):
        found.add("amend_after_consumption")
    return found


def explore(scenario: Scenario, mutant: str = "", max_states: int = 300_000) -> dict:
    start = (model.initial(scenario), spec.initial(scenario))
    nodes = [start]
    index = {start: 0}
    # Backpointers preserve shortest counterexamples without storing full traces.
    parents: list[tuple[int, Event] | None] = [None]
    depths = [0]
    queue = deque([0])
    edges = 0
    event_counts: Counter = Counter()
    covered: set[str] = set()

    def report(status: str, **extra) -> dict:
        return {
            "scenario": scenario.name,
            "mutant": mutant or None,
            "status": status,
            "states": len(nodes),
            "transitions": edges,
            "max_shortest_path": max(depths),
            "bounds": asdict(scenario),
            "coverage": sorted(covered),
            "event_edges": dict(sorted(event_counts.items())),
            **extra,
        }

    while queue:
        cursor = queue.popleft()
        state, audit = nodes[cursor]
        for event, successor in model.transitions(scenario, state, mutant):
            edges += 1
            event_counts[event.kind] += 1
            try:
                next_audit = spec.advance(scenario, audit, event)
                observe(scenario, next_audit, successor)
            except spec.Violation as failure:
                trace = [event]
                pointer = cursor
                while parents[pointer] is not None:
                    parent, prior = parents[pointer]
                    trace.append(prior)
                    pointer = parent
                trace.reverse()
                return report(
                    "counterexample",
                    invariant=failure.invariant,
                    reason=failure.reason,
                    shortest_counterexample=[event_json(e) for e in trace],
                )
            covered.update(coverage(scenario, state, event))
            node = (successor, next_audit)
            if node not in index:
                if len(nodes) >= max_states:
                    return report(
                        "incomplete", reason="state limit reached; NOT a safety result"
                    )
                index[node] = len(nodes)
                queue.append(len(nodes))
                nodes.append(node)
                parents.append((cursor, event))
                depths.append(depths[cursor] + 1)
    return report("exhausted")


def required_coverage(scenario: Scenario) -> set[str]:
    required = {"reserve", "emit:success", "terminal_first_success", "ack", "replay"}
    if len(scenario.slots) > 1 and scenario.contracts[0].predecessors[-1]:
        required.add("dependent_successor_admitted")
    if scenario.preflight_failure:
        required.add("settle:no_effect")
    if scenario.recovery:
        required |= {
            "policy_reopen",
            "executor_reopen",
            "retained_success_survives_executor_reopen",
            "settle:unknown",
        }
    if scenario.contracts[0].refund_no_effect and len(scenario.slots) > 1:
        required.add("retry_after_proven_no_effect")
    if len(scenario.contracts) > 1:
        required.add("amend_after_consumption")
    if scenario.revoke:
        required.add("already_reserved_attempt_after_revocation")
    return required


def run_trace(
    scenario: Scenario, requests: list[tuple[str, int, str]], mutant: str = ""
) -> tuple[model.State, spec.Audit]:
    """Execute directed witnesses for checker tests, checking every prefix.

    Tuples contain (event kind, request id or -1, outcome or empty).
    The first matching enabled transition is deterministic.
    """
    state, audit = model.initial(scenario), spec.initial(scenario)
    for kind, slot, outcome in requests:
        candidates = [
            (e, s)
            for e, s in model.transitions(scenario, state, mutant)
            if e.kind == kind and e.request == slot and e.outcome == outcome
        ]
        if not candidates:
            raise ValueError(f"disabled step {kind}/{slot}/{outcome}")
        event, state = candidates[0]
        audit = spec.advance(scenario, audit, event)
        observe(scenario, audit, state)
    return state, audit


def source_hashes() -> dict[str, str]:
    directory = Path(__file__).parent
    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(directory.glob("*.py"))
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, help="write deterministic generated JSON evidence"
    )
    parser.add_argument(
        "--check-recorded",
        type=Path,
        help="fail if regenerated evidence differs from this committed JSON",
    )
    parser.add_argument(
        "--scenario", choices=[s.name for s in SCENARIOS], action="append"
    )
    parser.add_argument("--baseline-only", action="store_true")
    parser.add_argument("--max-states", type=int, default=300_000)
    args = parser.parse_args()
    if args.max_states < 1:
        parser.error("--max-states must be positive")
    selected = [s for s in SCENARIOS if not args.scenario or s.name in args.scenario]
    baseline = []
    mutants = []
    for scenario in selected:
        result = explore(scenario, max_states=args.max_states)
        result["missing_positive_witnesses"] = sorted(
            required_coverage(scenario) - set(result["coverage"])
        )
        baseline.append(result)
        print(
            f"baseline {scenario.name}: {result['status']}; "
            f"{result['states']} states, {result['transitions']} transitions",
            flush=True,
        )
    if not args.baseline_only:
        for name, (scenario_name, expected) in MUTANTS.items():
            scenario = next(s for s in SCENARIOS if s.name == scenario_name)
            if scenario not in selected:
                continue
            result = explore(scenario, name, args.max_states)
            result["expected_invariant"] = expected
            mutants.append(result)
            print(
                f"mutant {name}: {result['status']} {result.get('invariant', '')}; "
                f"{len(result.get('shortest_counterexample', []))} events",
                flush=True,
            )
    valid = all(
        r["status"] == "exhausted" and not r["missing_positive_witnesses"]
        for r in baseline
    ) and all(
        r["status"] == "counterexample" and r["invariant"] == r["expected_invariant"]
        for r in mutants
    )
    output = {
        "schema": 1,
        "claim": (
            "finite model-to-spec safety exploration, "
            "not Rust refinement or empirical security evaluation"
        ),
        "complete_requested_run": valid,
        "sources_sha256": source_hashes(),
        "baseline": baseline,
        "mutants": mutants,
    }
    encoded = json.dumps(output, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    if args.check_recorded:
        recorded = json.loads(args.check_recorded.read_text(encoding="utf-8"))
        # JSON arrays round-trip to lists, whereas fixture dataclasses contain
        # tuples. Compare JSON values, not Python-only container representations.
        if recorded != json.loads(encoded):
            print(
                "recorded evidence differs; regenerate and inspect "
                "the changed model/scope/results",
                flush=True,
            )
            valid = False
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
