"""U5's timeline: a step's time is the interval between consecutive provider
attempts, and the task window is measured from the owner input commit."""
import unittest

from analysis.utility_improvements import episode_times


def event(kind, seconds, **fields):
    return dict(kind=kind, time_ns=int(seconds * 1e9), **fields)


class EpisodeTimesTests(unittest.TestCase):
    def test_times_run_from_the_owner_input_commit(self):
        events = [event("admission_stage_started", 10, stage="owner_input_authenticate"),
                  event("admission_stage_started", 11, stage="owner_input_commit"),
                  event("episode_binding", 13.4),
                  event("provider_attempt", 15), event("provider_attempt", 19),
                  event("provider_attempt", 23.5), event("episode_observation", 30)]
        times = episode_times(events)
        self.assertEqual(times["gaps"], [4.0, 4.5])
        self.assertEqual((times["binding"], times["observation"]), (2.4, 19.0))

    def test_an_episode_that_never_committed_has_no_window_times(self):
        times = episode_times([event("provider_attempt", 1), event("episode_observation", 2)])
        self.assertEqual((times["gaps"], times["binding"], times["observation"]), ([], None, None))


if __name__ == "__main__":
    unittest.main()
