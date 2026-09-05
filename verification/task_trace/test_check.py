"""Sanity/negative tests for the research checker itself."""

import ast
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from . import model, spec
from .check import explore, observe, required_coverage, run_trace
from .domain import MUTANTS, SCENARIOS, Event


def scenario(name):
    return next(s for s in SCENARIOS if s.name == name)


ROOT = [("issue", -1, ""), ("approve", 0, ""), ("reserve", 0, "")]


class TraceCheckerTests(unittest.TestCase):
    def test_implementation_model_does_not_import_specification(self):
        tree = ast.parse(Path(model.__file__).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                self.assertNotIn(node.module, ("spec", "check"))
            elif isinstance(node, ast.Import):
                self.assertFalse(
                    any(x.name.endswith((".spec", ".check")) for x in node.names)
                )

    def test_unknown_event_is_not_silently_allowed(self):
        s = scenario("relation")
        a = spec.advance(s, spec.initial(s), Event("issue", origin="task"))
        with self.assertRaises(ValueError):
            # Use a reserved record so failure is specifically missing semantics.
            _, a = run_trace(s, ROOT)
            spec.advance(s, a, Event("invented", 0))

    def test_state_limit_and_recorded_report_checks_fail_closed(self):
        self.assertEqual(
            explore(scenario("relation"), max_states=1)["status"], "incomplete"
        )
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            command = [
                sys.executable,
                "-m",
                "verification.task_trace.check",
                "--scenario",
                "relation",
            ]
            result = subprocess.run(
                command + ["--output", str(report)], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run(
                command + ["--check-recorded", str(report)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            data = json.loads(report.read_text())
            data["baseline"][0]["states"] += 1
            report.write_text(json.dumps(data))
            result = subprocess.run(
                command + ["--check-recorded", str(report)],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)

    def test_terminal_first_success_and_duplicate_replay(self):
        s = scenario("relation")
        steps = ROOT + [
            ("fence", 0, ""),
            ("emit", 0, "success"),
            ("retain", 0, "success"),
            ("certify", 0, "success"),
            ("settle", 0, "success"),
        ]
        state, audit = run_trace(
            s, steps + [("settle", 0, "success"), ("replay", 0, ""), ("ack", 0, "")]
        )
        self.assertEqual(state.attempts, (1,))
        self.assertEqual(audit.records[0].emits, 1)
        self.assertEqual(state.version, 3)

    def test_revoke_does_not_retroactively_cancel_reserved_attempt(self):
        s = scenario("revocation")
        state, audit = run_trace(
            s, ROOT + [("revoke", -1, ""), ("fence", 0, ""), ("emit", 0, "success")]
        )
        self.assertTrue(state.revoked)
        self.assertEqual(audit.records[0].emits, 1)
        self.assertFalse(
            any(e.kind == "reserve" for e, _ in model.transitions(s, state))
        )

    def test_executor_crash_after_fence_can_lose_work_not_resend(self):
        s = scenario("lost_fence")
        state, audit = run_trace(
            s,
            ROOT
            + [
                ("fence", 0, ""),
                ("executor_crash", -1, ""),
                ("executor_reopen", -1, ""),
                ("unknown", 0, ""),
                ("settle", 0, "unknown"),
            ],
        )
        self.assertEqual(audit.records[0].emits, 0)
        self.assertEqual(state.magnitude, (1,))
        self.assertFalse(any(e.kind == "emit" for e, _ in model.transitions(s, state)))

    def test_counter_oracle_uses_history_not_reported_counter(self):
        s = scenario("relation")
        state, audit = run_trace(s, ROOT)
        with self.assertRaisesRegex(spec.Violation, "S3"):
            observe(s, audit, replace(state, attempts=(0,)))

    def test_all_mutants_have_expected_counterexamples(self):
        for name, (which, expected) in MUTANTS.items():
            with self.subTest(mutant=name):
                result = explore(scenario(which), name)
                self.assertEqual(result["status"], "counterexample", result)
                self.assertEqual(result["invariant"], expected, result)

    def test_independent_spec_rejects_fabricated_and_mismatched_outcomes(self):
        s = scenario("relation")
        _, audit = run_trace(s, ROOT)
        for event in (
            Event("settle", 0, outcome="success"),
            Event("emit", 0, 2),
            Event("ack", 0),
        ):
            with self.subTest(event=event), self.assertRaises(spec.Violation):
                spec.advance(s, audit, event)
        # The independent language must not permit an effect after refund, even
        # if an implementation-shaped machine never happens to generate it.
        _, no_effect = run_trace(
            s, ROOT + [("no_effect", 0, ""), ("settle", 0, "no_effect")]
        )
        with self.assertRaisesRegex(spec.Violation, "S5"):
            spec.advance(s, no_effect, Event("fence", 0, 0))

    def test_baselines_exhaust_and_include_positive_witnesses(self):
        for s in SCENARIOS:
            with self.subTest(scenario=s.name):
                result = explore(s)
                self.assertEqual(result["status"], "exhausted", result)
                self.assertFalse(required_coverage(s) - set(result["coverage"]), result)

    def test_aba_amendment_does_not_resurrect_old_success(self):
        s = scenario("epoch_aba")
        state, _ = run_trace(
            s,
            ROOT
            + [
                ("fence", 0, ""),
                ("emit", 0, "success"),
                ("retain", 0, "success"),
                ("certify", 0, "success"),
                ("settle", 0, "success"),
                ("amend", -1, ""),
                ("amend", -1, ""),
            ],
        )
        # Select the valid successor tuple in the restored relation.
        event, approved = next(
            (e, nxt)
            for e, nxt in model.transitions(s, state)
            if e.kind == "approve" and e.request == 1 and e.action == 1
        )
        self.assertEqual(event.version, state.version)
        self.assertFalse(
            any(e.kind == "reserve" for e, _ in model.transitions(s, approved))
        )

    def test_numeric_amendment_preserves_success_but_not_free_budget(self):
        s = scenario("amendment")
        state, audit = run_trace(
            s,
            ROOT
            + [
                ("fence", 0, ""),
                ("emit", 0, "success"),
                ("retain", 0, "success"),
                ("certify", 0, "success"),
                ("settle", 0, "success"),
                ("amend", -1, ""),
            ],
        )
        event, approved = next(
            (e, nxt)
            for e, nxt in model.transitions(s, state)
            if e.kind == "approve" and e.request == 1 and e.action == 1
        )
        audit = spec.advance(s, audit, event)
        event, reserved = next(
            (e, nxt) for e, nxt in model.transitions(s, approved) if e.kind == "reserve"
        )
        audit = spec.advance(s, audit, event)
        observe(s, audit, reserved)
        self.assertEqual(reserved.attempts, (1, 1))
        self.assertEqual(reserved.epoch, 0)

    def test_third_attempt_cannot_use_two_no_effect_refunds(self):
        s = scenario("retry_limit")
        state, _ = run_trace(
            s,
            ROOT
            + [
                ("no_effect", 0, ""),
                ("settle", 0, "no_effect"),
                ("approve", 1, ""),
                ("reserve", 1, ""),
                ("no_effect", 1, ""),
                ("settle", 1, "no_effect"),
                ("approve", 2, ""),
            ],
        )
        self.assertEqual(state.attempts, (2,))
        self.assertEqual(state.magnitude, (0,))
        self.assertFalse(
            any(e.kind == "reserve" for e, _ in model.transitions(s, state))
        )

    def test_retained_response_can_fail_decode_without_gaining_success(self):
        s = scenario("recovery")
        state, audit = run_trace(
            s,
            ROOT
            + [
                ("fence", 0, ""),
                ("emit", 0, "success"),
                ("retain", 0, "success"),
                ("executor_crash", -1, ""),
                ("executor_reopen", -1, ""),
                ("unknown", 0, ""),
                ("settle", 0, "unknown"),
            ],
        )
        self.assertTrue(audit.records[0].retained)
        self.assertEqual(state.requests[0].status, "unknown")
        self.assertEqual(state.magnitude, (1,))
        self.assertFalse(any(e.kind == "emit" for e, _ in model.transitions(s, state)))


if __name__ == "__main__":
    unittest.main()
