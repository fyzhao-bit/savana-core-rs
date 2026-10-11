"""The crash-matrix table groups trials by the journal state a crash left."""
import unittest

from analysis import crash_matrix as cm


def trial(point, found, final, effects=(0, 0, 0, 0), bad=(), exit="killed"):
    child, recovery, replay, restart = effects
    return dict(point=point, exit=exit, found=list(found), recovered=list(final),
                replayed=list(final), restarted=list(final),
                effects=dict(child=child, recovery=recovery, replay=replay, restart=restart),
                bad=list(bad))


class CrashMatrixTests(unittest.TestCase):
    def test_a_started_effect_splits_at_the_first_provider_byte(self):
        before_byte = trial("after:3", ["EffectStarted"], ["Indeterminate"])
        after_byte = trial("provider", ["EffectStarted"], ["Indeterminate"], effects=(1, 0, 0, 0))
        self.assertEqual(cm.found(before_byte), "EffectStarted")
        self.assertEqual(cm.found(after_byte), "EffectStarted+request")

    def test_rows_follow_the_protocol_order_and_count_requests_and_bad_states(self):
        trials = [
            trial("none", ["Acknowledged"], ["Acknowledged"], (1, 0, 0, 0), exit="completed"),
            trial("provider", ["EffectStarted"], ["Indeterminate"], (1, 0, 0, 0)),
            trial("after:1", ["Prepared"], ["CompletionAvailable"], (0, 1, 0, 0)),
            trial("before:1", ["Prepared"], ["CompletionAvailable"], (0, 1, 0, 0)),
            trial("random:10us", [], ["CompletionAvailable"], (0, 0, 1, 0)),
            trial("after:2", ["ProviderAttemptPrepared"], ["Indeterminate"], (0, 1, 0, 0),
                  bad=["phantom"]),
        ]
        table = cm.rows(trials)
        self.assertEqual([r["state"] for r in table],
                         ["Prepared", "ProviderAttemptPrepared", "EffectStarted+request", "-"])
        self.assertEqual(table[0]["kills"], {"after": 1, "before": 1})
        self.assertEqual(table[0]["provider_requests"], {1: 2})
        self.assertEqual(table[1]["bad"], {"phantom": 1})
        summary = cm.summary(trials)
        self.assertEqual((summary["trials"], summary["bad_trials"], summary["max_provider_requests"]),
                         (5, 1, 1))
        # A resent dispatch that the executor never accepted is a first execution.
        self.assertEqual(summary["reissued_after_crash"], 0)
        self.assertIn("| Prepared | accepted, no attempt opened | 2 (after 1, before 1)",
                      cm.markdown(table))


if __name__ == "__main__":
    unittest.main()
