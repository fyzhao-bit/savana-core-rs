import argparse
import asyncio
import json
from pathlib import Path
import sys

from . import readiness, regressions
from .manifest import bind_results
from .metrics import Trial, paired_comparison, summarize


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def parse(text):
    def reject_constant(_):
        raise ValueError("nonfinite_json_number")
    return json.loads(text, object_pairs_hook=unique_object, parse_constant=reject_constant)


def read(path):
    with Path(path).open("rb") as handle:
        data = handle.read(16 * 1024 * 1024 + 1)
    if len(data) > 16 * 1024 * 1024:
        raise ValueError("input_too_large")
    return data.decode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="Savana experiments; protected runs require explicit deployment and model credentials.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("preflight")
    sub.add_parser("matrix")
    protected = sub.add_parser("agentdojo-protected", help="Official calendar subset through Python SDK; no fallback")
    protected.add_argument("--output", required=True, type=Path)
    protected.add_argument("--config", type=Path)
    protected.add_argument("--auth-fd", type=int)
    protected.add_argument("--model-key-fd", type=int)
    protected.add_argument("--model-listener-fd", type=int)
    protected_verify = sub.add_parser("verify-protected", help="Offline audit consistency and official-oracle replay")
    protected_verify.add_argument("directory", type=Path)
    native = sub.add_parser("agentdojo-native-probe", help="Synthetic native kernel to AgentDojo provider conformance; no LLM")
    native.add_argument("--kernel-test", required=True, help="Explicit trusted debug kernel test executable")
    native.add_argument("--output", required=True)
    native.add_argument("--timeout", type=int, default=45)
    regression = sub.add_parser("regressions")
    regression.add_argument("--timeout", type=int, default=600)
    loop = sub.add_parser("component-loop", help="Synthetic Rust private-workflow component, NOT full product")
    loop.add_argument("--driver", required=True)
    loop.add_argument("--output", required=True, help="New directory; existing results are never overwritten")
    loop.add_argument("--orders", type=int, nargs="+", default=[1, 2, 4])
    loop.add_argument("--seeds", type=int, nargs="+", default=[0])
    loop.add_argument("--policy", choices=["greedy", "refuse", "redirect", "replay", "stale", "unknown-handle"], default="greedy")
    loop.add_argument("--max-steps", type=int, default=48)
    loop.add_argument("--timeout", type=int, default=60)
    loop.add_argument("--model-config", help="Explicit trusted local executable config; no built-in cloud transport")
    suite = sub.add_parser("component-suite", help="Synthetic utility, attacks, reopen and stage timing; no models")
    suite.add_argument("--driver", required=True)
    suite.add_argument("--output", required=True)
    suite.add_argument("--orders", type=int, nargs="+", default=[1, 2, 4])
    suite.add_argument("--repetitions", type=int, default=2)
    suite.add_argument("--timeout", type=int, default=30)
    summary = sub.add_parser("summarize")
    summary.add_argument("--manifest", required=True)
    summary.add_argument("--results", required=True, help="One Trial JSON object per line")
    summary.add_argument("--compare", nargs=2, metavar=("BASELINE", "DEFENDED"))
    args = parser.parse_args()
    try:
        code = 0
        if args.command == "preflight":
            output, code = readiness.report(), 2
        elif args.command == "matrix":
            output = parse(read(Path(__file__).resolve().parents[1] / "model-matrix.json"))
        elif args.command == "agentdojo-protected":
            from .protected_agentdojo import load_config, run
            output = run(output=args.output, config=load_config(args.config) if args.config else None,
                auth_fd=args.auth_fd, model_key_fd=args.model_key_fd, model_listener_fd=args.model_listener_fd)
            code = 0 if output["run_status"] == "complete" else 2
        elif args.command == "verify-protected":
            from .protected_verify import verify
            output = verify(args.directory)
        elif args.command == "agentdojo-native-probe":
            from .agentdojo_native import run
            output = asyncio.run(run(kernel_test=args.kernel_test, output=args.output, timeout=args.timeout))
            code = int(output["passed"] != output["total"])
        elif args.command == "regressions":
            if not 1 <= args.timeout <= 3600:
                raise ValueError("invalid_timeout")
            output = regressions.run(args.timeout, lambda row: print(json.dumps(row), file=sys.stderr, flush=True))
            code = 0 if output["passed"] == output["total"] else 1
        elif args.command == "component-suite":
            from .component_suite import run
            output = asyncio.run(run(driver=args.driver, output=args.output, orders=args.orders,
                repetitions=args.repetitions, timeout=args.timeout))
            code = int(any(g["unknown"] or g["violation_count"] or g["recovery_failed_trials"] for g in output["groups"]))
        elif args.command == "component-loop":
            from .component_loop import run
            output = asyncio.run(run(driver=args.driver, output=args.output, orders=args.orders,
                seeds=args.seeds, policy=args.policy, max_steps=args.max_steps, timeout=args.timeout,
                model=parse(read(args.model_config)) if args.model_config else None))
            code = 1 if any(g["statuses"].get("error", 0) or g["statuses"].get("timeout", 0) for g in output["groups"]) else 0
        else:
            manifest = parse(read(args.manifest))
            trials = [Trial(**parse(line)) for line in read(args.results).splitlines() if line.strip()]
            trials = bind_results(manifest, trials)
            output = {"scope": manifest["scope"], "production_acceptance": False,
                      "groups": summarize(trials)}
            if args.compare:
                output["paired"] = paired_comparison(trials, *args.compare)
        print(json.dumps(output, indent=2, allow_nan=False))
        return code
    except (ValueError, TypeError, KeyError, OSError, RuntimeError) as error:
        # No exception messages: inputs may include private paths or strings.
        print(json.dumps({"error": type(error).__name__, "result": "invalid_or_blocked"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
