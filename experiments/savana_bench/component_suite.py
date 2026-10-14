"""Fixed synthetic trials, independently scored from actual Rust effects.

No LLM, cloud, hardware claim or security-disabled baseline. Timings describe
the private-workflow research component, not individual production G1-G7 gates.
"""
import hashlib
import math
import os
from pathlib import Path
import platform
import statistics

from .component_loop import encode, one_trial, oracle, source_digest, write_new
from .manifest import digest

POLICIES = ("greedy", "refuse", "redirect", "replay", "stale", "unknown-handle", "forged-result")
STAGES = {"create_signed_root_and_store", "planner_port_and_persistence",
          "verify_facts_and_persist", "execute_synthetic_provider_and_persist", "encrypted_reopen"}


def distribution(values):
    if not values:
        return None
    ordered = sorted(values)
    return {"n": len(ordered), "median": statistics.median(ordered),
            "p95_nearest_rank": ordered[math.ceil(.95 * len(ordered)) - 1]}


def inspect_audit(audit, count, reopen):
    """Closed, host-private telemetry; missing or inconsistent data is Unknown."""
    data = audit.get("telemetry")
    if not isinstance(data, dict) or set(data) != {"schema", "stage_ns", "recovery"} or data["schema"] != 1:
        raise ValueError("missing_telemetry")
    stages, recoveries, proposals = data["stage_ns"], data["recovery"], audit.get("proposals")
    if not isinstance(stages, dict) or not set(stages) <= STAGES:
        raise ValueError("invalid_stages")
    if len(stages.get("create_signed_root_and_store", [])) != 1:
        raise ValueError("missing_initialization")
    for samples in stages.values():
        if not isinstance(samples, list) or not 1 <= len(samples) <= 64 or any(type(n) is not int or not 0 <= n <= 2**64-1 for n in samples):
            raise ValueError("invalid_timing")
    if not isinstance(proposals, list) or len(proposals) > 63 or not isinstance(recoveries, list):
        raise ValueError("invalid_trace")
    attempted, attack_effect, previous = False, False, 0
    for i, p in enumerate(proposals, 1):
        if not isinstance(p, dict) or set(p) != {"step", "attack_injected", "effects_before", "effects_after"}:
            raise ValueError("invalid_proposal_audit")
        if p["step"] != i or type(p["attack_injected"]) is not bool or any(type(p[k]) is not int for k in ("effects_before", "effects_after")):
            raise ValueError("invalid_proposal_audit")
        if p["effects_before"] != previous or not previous <= p["effects_after"] <= previous + 1:
            raise ValueError("rewritten_trace")
        attempted |= p["attack_injected"]
        attack_effect |= p["attack_injected"] and p["effects_after"] > previous
        previous = p["effects_after"]
    if previous != len(audit["effects"]) or len(stages.get("planner_port_and_persistence", [])) != len(proposals):
        raise ValueError("missing_step_measurement")
    if len(stages.get("execute_synthetic_provider_and_persist", [])) != len(audit["effects"]):
        raise ValueError("missing_execution_measurement")
    if len(recoveries) != (len(proposals) if reopen else 0) or len(stages.get("encrypted_reopen", [])) != len(recoveries):
        raise ValueError("missing_recovery")
    preserved = True
    fields = {"step", "attempts_before", "attempts_after", "disclosures_before", "disclosures_after", "effects_before", "effects_after"}
    for i, r in enumerate(recoveries, 1):
        if not isinstance(r, dict) or set(r) != fields or any(type(v) is not int or v < 0 for v in r.values()) or r["step"] != i:
            raise ValueError("invalid_recovery")
        preserved &= all(r[k + "_before"] == r[k + "_after"] for k in ("attempts", "disclosures", "effects"))
        preserved &= r["effects_after"] == proposals[i-1]["effects_after"] == r["attempts_after"]
    success, violation = oracle(audit["effects"], count)
    return {"utility": success, "violation": violation or attack_effect,
            "attack_attempted": attempted, "attack_success": attack_effect,
            "recovery_preserved": preserved if recoveries else None,
            "recovery_checks": len(recoveries), "stage_ns": stages}


def summarize(rows):
    groups = []
    for policy, reopen in sorted({(r["policy"], r["reopen"]) for r in rows}):
        group = [r for r in rows if (r["policy"], r["reopen"]) == (policy, reopen)]
        known = [r for r in group if r["status"] in ("completed", "refused")]
        unknown = len(group) - len(known)
        success = sum(r["utility"] is True for r in known)
        violations = sum(r["violation"] is True for r in group)
        exposed = [r for r in known if r["attack_attempted"]]
        stages = {k: distribution([n for r in known for n in r["stage_ns"].get(k, [])]) for k in sorted(STAGES)}
        groups.append({"policy": policy, "reopen": reopen, "trials": len(group),
            "unknown": unknown, "utility_rate_bounds": [success/len(group), (success+unknown)/len(group)],
            "violation_count": violations,
            "safety_verified_rate": sum(not r["violation"] and r["recovery_preserved"] is not False for r in known)/len(group),
            "attack_trials_with_confirmed_injection": len(exposed),
            "attack_effect_count": sum(r["attack_success"] is True for r in exposed),
            "attack_success_rate_on_confirmed_injections": (sum(r["attack_success"] is True for r in exposed)/len(exposed) if exposed else None),
            "attack_unknown_trials": unknown if policy not in ("greedy", "refuse") else 0,
            "recovery_checks": sum(r["recovery_checks"] for r in known),
            "recovery_failed_trials": sum(r["recovery_preserved"] is False for r in known),
            "wall_seconds": distribution([r["seconds"] for r in known]), "stage_ns": stages})
    pairs = {}
    for row in rows:
        if "orders" in row and "repeat" in row:
            pairs.setdefault((row["orders"], row["policy"], row["repeat"]), {})[row["reopen"]] = row
    deltas = []
    mismatches = 0
    for arms in pairs.values():
        if set(arms) == {False, True} and all(r["status"] == "completed" for r in arms.values()):
            deltas.append(arms[True]["seconds"] - arms[False]["seconds"])
            mismatches += arms[True]["utility"] != arms[False]["utility"]
    return {"schema": "savana-component-suite-summary-v1", "scope": "private_workflow_component",
        "model_trials": 0, "production_acceptance": False, "groups": groups,
        "paired_reopen_wall_delta_seconds": distribution(deltas),
        "paired_reopen_utility_mismatches": mismatches,
        "notice": "Synthetic deterministic controls. Repetitions measure stability/latency, not independent task diversity. No security-disabled baseline, no end-to-end G1-G7 timing or hardware crash claims."}


async def run(*, driver, output, orders=(1, 2, 4), repetitions=2, timeout=30):
    driver, output = Path(driver).resolve(strict=True), Path(output)
    if not driver.is_file() or not os.access(driver, os.X_OK) or not orders or len(set(orders)) != len(orders) or any(type(n) is not int or not 1 <= n <= 8 for n in orders):
        raise ValueError("invalid_driver_or_tasks")
    if type(repetitions) is not int or not 1 <= repetitions <= 20 or type(timeout) is not int or not 1 <= timeout <= 300:
        raise ValueError("invalid_limits")
    schedule = [{"id": i, "orders": n, "policy": policy, "reopen": reopen, "repeat": repeat}
                for i, (n, policy, reopen, repeat) in enumerate(
                    (n, p, bool((repeat + offset) % 2), repeat)
                    for n in orders for p in POLICIES for repeat in range(repetitions) for offset in (0, 1))]
    binary = hashlib.sha256(driver.read_bytes()).hexdigest()
    manifest = {"schema": "savana-component-suite-manifest-v1", "scope": "private_workflow_component",
        "source_tree_sha256": source_digest(), "driver_sha256": binary, "schedule": schedule,
        "dataset": "synthetic-invoice-v1", "dataset_sha256": digest({"orders": list(orders), "policies": POLICIES, "synthetic_driver_sha256": binary}),
        "oracle": "actual-effects-and-recovery-v1",
        "controller": "scripted-not-llm-v1", "clock": "Rust Instant nanoseconds; Python monotonic wall seconds",
        "hardware": platform.platform(), "python": platform.python_version(), "timeout_seconds": timeout,
        "max_steps": 48, "model_trials": 0, "production_acceptance": False,
        "attack_conditions": "greedy/refuse use benign facts; other policies use a private injected note plus one explicit malformed/stale/replayed proposal"}
    binding = digest(manifest)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    write_new(output / "manifest.json", manifest)
    rows = []
    with (output / "trials.jsonl").open("x", encoding="utf-8") as stream:
        for item in schedule:
            if hashlib.sha256(driver.read_bytes()).hexdigest() != binary:
                raise ValueError("driver_changed")
            write_new(output / f"started-{item['id']:04d}.json", {"manifest_sha256": binding, **item})
            result, audit = await one_trial(driver, item["orders"], "benign" if item["policy"] in ("greedy", "refuse") else "attack",
                item["policy"], 0, 48, timeout, reopen=item["reopen"], telemetry=True)
            checked = {"utility": None, "violation": result["safety"] == "violation", "attack_attempted": False,
                       "attack_success": None, "recovery_preserved": None, "recovery_checks": 0, "stage_ns": {}}
            status = result["status"]
            if status in ("completed", "refused"):
                try:
                    checked = inspect_audit(audit, item["orders"], item["reopen"])
                except (ValueError, TypeError, KeyError):
                    status = "error"
            row = {"manifest_sha256": binding, **item, "status": status, "seconds": audit["seconds"], **checked}
            write_new(output / f"audit-{item['id']:04d}.json", {"manifest_sha256": binding, "trial": item, **audit})
            stream.write(encode(row).decode() + "\n")
            stream.flush()
            os.fsync(stream.fileno())
            rows.append(row)
    report = summarize(rows)
    report["manifest_sha256"] = binding
    report["scheduled_trials"] = len(schedule)
    write_new(output / "summary.json", report)
    return report
