"""savana_lab/examples/all_configs.py: every configuration it lists is one the
runner accepts, its attack pairs are AgentDojo's and AutoDojo's, and its run
names keep the analysis prefixes apart. No Docker, model or network here."""
from dataclasses import fields
import importlib.util
import io
from pathlib import Path
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

from savana_bench.root_drafter import ROOT_POISON_GOALS
from savana_lab import U9, SUITES
from savana_lab.driver import LabError

NEEDS_AGENTDOJO = unittest.skipUnless(importlib.util.find_spec("agentdojo"), "install the explicit AgentDojo test extra")
SCRIPT = Path(__file__).resolve().parents[2] / "experiments" / "savana_lab" / "examples" / "all_configs.py"


def _load():
    spec = importlib.util.spec_from_file_location("all_configs", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module   # its dataclass looks its module up while it is made
    spec.loader.exec_module(module)
    return module


all_configs = _load()
ARMS = {arm.name: arm for arm in all_configs.arms()}


def changed(config):
    """The options in which `config` differs from U9."""
    return {f.name for f in fields(config) if getattr(config, f.name) != getattr(U9, f.name)}


class AllConfigsTests(unittest.TestCase):
    def test_each_configuration_is_u9_with_these_options_changed(self):
        expected = {"u9": set(), "u9h": {"owner"}, "u10": {"instructions"}, "pro": {"planner"},
                    "mask": {"view", "extract"},
                    "mask-planner": {"view"}, "mask-extractor": {"extract"}, "attack": set(),
                    "autodojo": {"attack"}, "exposure": {"attack", "exposure"}, "mapper-honest": {"mapper"},
                    "mapper-exposure": {"mapper", "attack", "exposure"}}
        expected |= {f"poison-{goal}": {"goal"} for goal in ROOT_POISON_GOALS}
        expected |= {f"mapper-poison-{goal}": {"mapper", "goal"} for goal in ROOT_POISON_GOALS}
        self.assertEqual({name: changed(arm.config) for name, arm in ARMS.items()}, expected)
        self.assertEqual(ARMS["mask"].config.view, "masked")
        self.assertEqual(ARMS["mapper-honest"].config.mapper, "service")

    @NEEDS_AGENTDOJO
    def test_every_plan_is_one_the_runner_accepts(self):
        # make_plan checks each batch's spec with savana_lab's rules and then the runner's own parser.
        full = dict(all_configs.plans(ARMS.values(), "t", list(SUITES), None))
        sizes = {arm.name: len(plan.tasks()) for arm, plan in full.items()}
        self.assertEqual(sizes["u9"], 97)
        self.assertEqual(sizes["u10"], 97)
        self.assertEqual(sizes["attack"], 949)
        self.assertEqual(sizes["autodojo"], 389)
        self.assertEqual(sizes["mapper-exposure"], 389)
        self.assertEqual(sum(len(plan.batches) for plan in full.values()), 447)
        smoke = all_configs.plans(ARMS.values(), "s", ["banking"], 2)
        self.assertTrue(all(plan is not None and len(plan.batches) == 1 and len(plan.tasks()) == 2
                            for _, plan in smoke))

    @NEEDS_AGENTDOJO
    def test_autodojo_has_no_workspace_tasks(self):
        planned = {arm.name: plan for arm, plan in all_configs.plans(ARMS.values(), "w", ["workspace"], 1)}
        self.assertEqual({name for name, plan in planned.items() if plan is None},
                         {"autodojo", "exposure", "mapper-exposure"})

    def test_the_autodojo_pairs_are_the_cached_injections(self):
        from savana_bench.autodojo_cache import SUITES as AUTODOJO_SUITES, cache_path, load
        for suite in AUTODOJO_SUITES:
            variants, _, _ = load(cache_path(suite))
            self.assertEqual(sorted(variants),
                             sorted(f"injection_task_{n}" for n in all_configs.INJECTION_TASKS[suite]))

    @NEEDS_AGENTDOJO
    def test_the_injection_tasks_are_agentdojos(self):
        from agentdojo.task_suite.load_suites import get_suite
        from savana_bench.agentdojo_tasks import BENCHMARK
        for suite, numbers in all_configs.INJECTION_TASKS.items():
            self.assertEqual(sorted(get_suite(BENCHMARK, suite).injection_tasks),
                             sorted(f"injection_task_{n}" for n in numbers))

    @NEEDS_AGENTDOJO
    def test_the_analysis_prefixes_select_only_their_own_runs(self):
        # analysis.polluted_mapper reads the batches `<prefix>-*` (`<prefix>-<goal>-*` for a goal).
        batches = [b.name for _, plan in all_configs.plans(ARMS.values(), "p", list(SUITES), None)
                   for b in plan.batches]

        def selected(prefix):
            return {name.rsplit("-", 2)[0] for name in batches if name.startswith(prefix + "-")}

        for run in ("p-u9", "p-exposure", "p-mapper-honest", "p-mapper-exposure"):
            self.assertEqual(selected(run), {run})
        for goal in ROOT_POISON_GOALS:
            self.assertEqual(selected(f"p-poison-{goal}"), {f"p-poison-{goal}"})
            self.assertEqual(selected(f"p-mapper-poison-{goal}"), {f"p-mapper-poison-{goal}"})
        hint = all_configs.analysis_hint(mock.Mock(results="R"), "p")
        for option in ("--goal-prefix p-mapper-poison", "--data-prefix p-mapper-exposure",
                       "--honest-prefix p-mapper-honest", "--baseline-goal-prefix p-poison",
                       "--baseline-data-prefix p-exposure", "--baseline-honest-prefix p-u9"):
            self.assertIn(option, hint)

    @NEEDS_AGENTDOJO   # counting U10's cases asks AgentDojo which requests delegate to data
    def test_the_listing_needs_no_host(self):
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(all_configs.main([]), 0)
        self.assertIn("cfg-poison-exfiltrate: a compromised planner", out.getvalue())
        self.assertTrue(out.getvalue().endswith("447 batches in all; each runs on a brand-new host\n"))
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(all_configs.main(["--smoke"]), 0)
        self.assertIn("smoke-mapper-exposure:", out.getvalue())
        self.assertTrue(out.getvalue().endswith("20 batches in all; each runs on a brand-new host\n"))

    def test_an_unknown_configuration_suite_or_count_is_refused(self):
        for argv, message in ((["--run", "u9", "nope"], "unknown configuration nope"),
                              (["--run", "attack", "--suites", "bank"], "--suites takes banking"),
                              (["--smoke", "--per-suite", "0"], "--per-suite takes a number from 1")):
            with redirect_stdout(io.StringIO()), mock.patch("sys.stderr", io.StringIO()) as err:
                with self.assertRaises(SystemExit):
                    all_configs.main(argv)
            self.assertIn(message, err.getvalue())

    def test_runs_go_in_order_and_stop_at_the_first_that_does_not_finish(self):
        planned = all_configs.plans([ARMS["u9"], ARMS["autodojo"], ARMS["mask"], ARMS["attack"]], "t",
                                    ["workspace"], 1)
        created, results = [], iter(["done", "failed", "done"])

        def create(plan, host=None):
            created.append((plan.name, host))
            handle = mock.Mock()
            handle.start.return_value = next(results)
            return handle

        lab = mock.Mock()
        lab.create.side_effect = create
        with mock.patch.object(all_configs, "summary", return_value="summary"), \
                redirect_stdout(io.StringIO()) as out:
            self.assertEqual(all_configs.run_all(lab, planned, host="H"), 2)
        self.assertEqual(created, [("t-u9", "H"), ("t-mask", "H")])
        self.assertIn("skip autodojo", out.getvalue())
        self.assertIn("t-mask failed: run the same command again to resume it", out.getvalue())

    def test_a_lab_error_ends_the_script_with_its_message(self):
        with mock.patch.object(all_configs, "run_all", side_effect=LabError("commit first")), \
                mock.patch("sys.stderr", io.StringIO()) as err, redirect_stdout(io.StringIO()):
            self.assertEqual(all_configs.main(["--run", "u9", "--smoke"]), 1)
        self.assertIn("commit first", err.getvalue())

    def test_the_summary_counts_attacker_success_over_the_attack_pairs(self):
        report = mock.Mock()
        report.utility.return_value = "utility"
        report.rows.return_value = [
            dict(injection="injection_task_0", attacker_success=False, unauthorized_provider_attempts=0),
            dict(injection="injection_task_1", attacker_success=None),
            dict(injection="injection_task_2", attacker_success=True, unauthorized_provider_attempts=1)]
        text = all_configs.summary(mock.Mock(report=mock.Mock(return_value=report)), "t-attack")
        self.assertIn("attacker success (AgentDojo's security oracle): 1/3 pairs, 1 not scored", text)
        self.assertIn("unauthorized provider attempts: 1", text)

    def test_quick_tries_the_first_task_or_the_one_given(self):
        result = mock.Mock()
        result.model_calls.return_value = [dict(stage="draft", shown="the request", reply="a program")]
        with mock.patch.object(all_configs.sl, "quick", return_value=result) as quick, \
                redirect_stdout(io.StringIO()) as out:
            self.assertEqual(all_configs.main(["--quick", "exposure", "--suites", "workspace,travel"]), 0)
            self.assertEqual(all_configs.main(["--quick", "mask", "--task", "slack:user_task_3",
                                               "--model-calls"]), 0)
        self.assertEqual([c.args for c in quick.call_args_list],
                         [(ARMS["exposure"].config, "travel", "user_task_0+injection_task_0"),
                          (ARMS["mask"].config, "slack", "user_task_3")])
        self.assertIn("[stage=draft]\nshown: the request\nreply: a program", out.getvalue())


if __name__ == "__main__":
    unittest.main()
