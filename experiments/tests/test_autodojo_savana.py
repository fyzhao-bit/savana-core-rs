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
