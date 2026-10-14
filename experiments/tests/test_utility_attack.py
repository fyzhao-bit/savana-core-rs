"""U8SX's attack summary: the earlier configuration it is set against counts
only the same pairs, per suite."""
import unittest

from analysis.utility_improvements import attack_summary


def attacked(suite, user, injection, **fields):
    row = dict(suite=suite, user=user, injection=injection, outcome="published", utility=False, success=False,
               data_chosen_steps=0, attacker_chose_address=False, directory_refused=False, attacker_address=False,
               attacker_text=False, dispatched_unapproved=0, unauthorized=0)
    return dict(row, **fields)


def earlier(suite, user, injection, utility, success):
    return dict(suite=suite, user=user, injection=injection, utility=utility, observed_attacker_success=success)


class AttackSummaryTests(unittest.TestCase):
    def test_the_baseline_counts_only_the_same_pairs_per_suite(self):
        rows = [attacked("banking", "user_task_0", "injection_task_1", utility=True),
                attacked("slack", "user_task_5", "injection_task_3", outcome="owner_refused", attacker_text=True)]
        baseline = [earlier("banking", "user_task_0", "injection_task_1", None, False),
                    # Not a pair of this run: left out.
                    earlier("banking", "user_task_0", "injection_task_2", True, True),
                    earlier("slack", "user_task_5", "injection_task_3", True, False)]
        summary = attack_summary(rows, baseline)
        self.assertEqual(summary["baseline"], dict(banking=dict(pairs=1, utility=0, success=0),
                                                   slack=dict(pairs=1, utility=1, success=0),
                                                   total=dict(pairs=2, utility=1, success=0)))
        self.assertEqual(summary["by_suite"]["total"]["utility"], 1)
        self.assertEqual(summary["by_suite"]["slack"]["attacker_text"], 1)
        self.assertNotIn("travel", summary["by_suite"])
        self.assertEqual(summary["successes"], [])

    def test_a_success_is_listed(self):
        summary = attack_summary([attacked("banking", "user_task_0", "injection_task_1", success=True,
                                           attacker_address=True)])
        self.assertEqual(summary["by_suite"]["banking"]["success"], 1)
        self.assertEqual(summary["successes"], [dict(suite="banking", user="user_task_0", injection="injection_task_1",
                                                     outcome="published", attacker_address=True,
                                                     attacker_text=False)])
        self.assertEqual(summary["baseline"], {})


if __name__ == "__main__":
    unittest.main()
