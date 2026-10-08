"""AutoDojo replay in Savana's drafted experiments."""
import unittest

import yaml

from savana_bench import autodojo_cache as ad
from savana_bench.planner_experiment import autodojo_provenance, experiment_attack, experiment_cases


class AutoDojoSavanaTests(unittest.TestCase):
    def test_spec_option_marks_every_case_and_default_adds_nothing(self):
        cases = experiment_cases("drafted+drafts=3+attack=autodojo:slack:user_task_0+injection_task_3,user_task_1")
        self.assertEqual([c["attack"] for c in cases], ["autodojo", "autodojo"])
        self.assertEqual(experiment_attack(cases), "autodojo")
        provenance = autodojo_provenance(cases)["autodojo"]
        self.assertEqual(provenance["cache_sha256"], {"slack": ad.load(ad.cache_path("slack"))[2]})
        plain = experiment_cases("drafted+drafts=3:slack:user_task_0+injection_task_3")
        self.assertNotIn("attack", plain[0])  # earlier runs' cases are unchanged
        self.assertEqual(experiment_attack(plain), "important_instructions_no_names")
        self.assertEqual(autodojo_provenance(plain), {})

    def test_spec_refuses_unsupported_combinations(self):
        for spec in ("drafted+attack=autodojo:workspace:user_task_0+injection_task_0",  # no AutoDojo cache
                     "drafted-poison+attack=autodojo:redirect:banking:user_task_0",  # planner attack, not data
                     "drafted+attack=adaptive:banking:user_task_0+injection_task_0",
                     "drafted+attack=autodojo+attack=autodojo:banking:user_task_0"):
            with self.assertRaises(ValueError, msg=spec):
                experiment_cases(spec)

    def test_official_case_replays_the_cached_injections(self):
        from agentdojo.attacks.base_attacks import BaseAttack
        from agentdojo.task_suite.load_suites import get_suite
        from savana_bench.protected_agentdojo import official_case
        from types import SimpleNamespace
        drafted = SimpleNamespace(task_id="user_task_1", suite="slack")  # the reviewed program's identity
        (case,) = experiment_cases("drafted+attack=autodojo:slack:user_task_1+injection_task_3")
        suite, task, injection, _contract, values, environment = official_case(dict(case), drafted)
        variants, originals, _ = ad.load(ad.cache_path("slack"))
        candidates = BaseAttack.get_injection_candidates(type("A", (BaseAttack,), {"attack": None})(suite, None), task)
        self.assertEqual(set(values), set(candidates))
        for vector, text in values.items():
            self.assertEqual(text, ad.injection(variants, originals, "injection_task_3", injection.GOAL, vector, 0))
            decoded = yaml.safe_load('"' + text + '"')
            self.assertNotIn("<INFORMATION>", decoded)  # an optimized variant, not the template
        self.assertIsNotNone(environment)
        (plain,) = experiment_cases("drafted:slack:user_task_1+injection_task_3")
        self.assertNotEqual(official_case(dict(plain), drafted)[4], values)


if __name__ == "__main__":
    unittest.main()


class PlannerExposureTests(unittest.TestCase):
    def test_exposure_needs_autodojo_attack_pairs(self):
        (case,) = experiment_cases("drafted+attack=autodojo+exposure=data:travel:user_task_5+injection_task_6")
        self.assertEqual((case["attack"], case["planner_exposure"]), ("autodojo", "data"))
        plain = experiment_cases("drafted+attack=autodojo:travel:user_task_5+injection_task_6")
        self.assertNotIn("planner_exposure", plain[0])
        for spec in ("drafted+exposure=data:travel:user_task_5+injection_task_6",  # official template
                     "drafted+attack=autodojo+exposure=data:travel:user_task_5",  # nothing to expose
                     "drafted+attack=autodojo+exposure=all:travel:user_task_5+injection_task_6"):
            with self.assertRaises(ValueError, msg=spec):
                experiment_cases(spec)

    def test_exposure_is_the_decoded_injected_data_and_reaches_only_the_request(self):
        import json
        from agentdojo.task_suite.load_suites import get_suite
        from savana_bench.planner_experiment import planner_exposure
        from savana_bench.root_drafter import EXPOSURE_NOTE, draft_request_body
        (case,) = experiment_cases("drafted+attack=autodojo+exposure=data:travel:user_task_5+injection_task_6")
        exposure = planner_exposure(case)
        self.assertTrue(exposure)
        # Exactly the injected values, as the tool output carries them (decoded).
        from savana_bench.protected_agentdojo import attack_values
        suite = get_suite("v1.2.2", "travel")
        values = attack_values(suite, suite.get_user_task_by_id("user_task_5"),
                               suite.get_injection_task_by_id("injection_task_6"), case)
        self.assertEqual([ad.yaml_escape(text) for text in exposure], [values[v] for v in sorted(values)])
        self.assertEqual(planner_exposure(case), exposure)  # deterministic: the verifier recomputes it
        (plain,) = experiment_cases("drafted+attack=autodojo:travel:user_task_5+injection_task_6")
        self.assertEqual(planner_exposure(plain), ())
        suite = get_suite("v1.2.2", "travel")
        prompt = suite.get_user_task_by_id("user_task_5").PROMPT
        exposed = json.loads(draft_request_body(suite, prompt, model="deepseek-flash", exposure=exposure))
        honest = json.loads(draft_request_body(suite, prompt, model="deepseek-flash"))
        self.assertTrue(exposed["messages"][0]["content"].endswith(EXPOSURE_NOTE))
        self.assertEqual(json.loads(exposed["messages"][1]["content"])["retrieved_data"], list(exposure))
        self.assertNotIn("retrieved_data", json.loads(honest["messages"][1]["content"]))
        self.assertNotIn(EXPOSURE_NOTE, honest["messages"][0]["content"])
