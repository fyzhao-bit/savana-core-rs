"""U5's timeline: a step's time is the interval between consecutive provider
attempts, and the task window is measured from the owner input commit. The
contention rule reads plain steps only: ones that call no model and start
while no earlier unfinished task is live."""
import base64
import json
import unittest

from analysis.utility_improvements import episode_times, pace


def event(kind, seconds, **fields):
    return dict(kind=kind, time_ns=int(seconds * 1e9), **fields)


def attempt(seconds, tool):
    payload = dict(jsonrpc="2.0", id="x", method="tools/call", params=dict(name=tool, arguments={}))
    return event("provider_attempt", seconds, payload_base64=base64.b64encode(json.dumps(payload).encode()).decode())


def committed(seconds, *attempts):
    return [event("admission_stage_started", seconds, stage="owner_input_commit"), *attempts]


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
        self.assertEqual(times["attempts"][0], (15 * 10**9, None))

    def test_an_episode_that_never_committed_has_no_window_times(self):
        times = episode_times([event("provider_attempt", 1), event("episode_observation", 2)])
        self.assertEqual((times["gaps"], times["binding"], times["observation"]), ([], None, None))

    def test_each_attempt_names_the_tool_it_called(self):
        times = episode_times([attempt(1, "dojo.slack.channels"), attempt(5, "dojo.model.extract")])
        self.assertEqual([tool for _time, tool in times["attempts"]], ["dojo.slack.channels", "dojo.model.extract"])


class PaceTests(unittest.TestCase):
    def test_a_plain_step_calls_no_model_and_waits_for_no_live_task(self):
        local = {
            # Refused after its first step: its task stays live until 60 s after its commit.
            0: committed(0, attempt(2, "dojo.slack.channels"), attempt(6, "dojo.slack.send_channel")),
            # Inside that window every step waits for it as well.
            1: committed(10, attempt(12, "dojo.slack.channels"), attempt(20, "dojo.slack.read_channel"),
                         attempt(28, "dojo.slack.send_dm")),
            # After it, a read takes 4 s; the step after an extraction includes the model call.
            2: committed(70, attempt(72, "dojo.slack.channels"), attempt(76, "dojo.model.extract"),
                         attempt(83, "dojo.slack.send_dm")),
        }
        rows = [dict(episode=2, outcome="published"), dict(episode=0, outcome="owner_refused"),
                dict(episode=1, outcome="published")]
        batch = pace(rows, local)
        self.assertEqual((batch["intervals"], batch["median_step_seconds"]), (5, 7.0))
        self.assertEqual((batch["plain_steps"], batch["median_plain_step_seconds"], batch["contended"]),
                         (2, 4.0, False))

    def test_slow_plain_steps_mark_contention(self):
        local = {0: committed(0, attempt(1, "dojo.bank.get_balance"), attempt(7, "dojo.bank.get_iban"),
                              attempt(13, "dojo.bank.send_money"))}
        batch = pace([dict(episode=0, outcome="published")], local)
        self.assertEqual((batch["median_plain_step_seconds"], batch["contended"]), (6.0, True))

    def test_without_a_plain_step_contention_is_unknown(self):
        local = {0: committed(0, attempt(1, "dojo.model.extract"), attempt(9, "dojo.slack.send_dm"))}
        self.assertIsNone(pace([dict(episode=0, outcome="published")], local)["contended"])


if __name__ == "__main__":
    unittest.main()
