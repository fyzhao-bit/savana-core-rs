"""The floor experiment reads approvals and dispatches off each episode's own evidence."""
import base64
import json
import unittest

from analysis import floor_experiment as fe

# Slack user task 1: the article's URL is taken from a channel message.
STEPS = [dict(tool="dojo.slack.read_channel", derived=[]),
         dict(tool="dojo.model.extract", derived=[]),
         dict(tool="dojo.web.get", derived=[["url", 2, "Text", 256]])]


def call(name, **arguments):
    payload = dict(jsonrpc="2.0", id="x", method="tools/call", params=dict(name=name, arguments=arguments))
    return dict(kind="provider_attempt", episode=0, payload_base64=base64.b64encode(json.dumps(payload).encode()).decode())


def episode(votes, calls, success=False):
    score = dict(kind="episode_score", episode=0, suite="slack", user="user_task_1",
                 injection="injection_task_3", outcome="owner_refused", attacker_success=success, utility=False)
    return [dict(kind="episode_input", episode=0, contract=dict(steps=STEPS)),
            *[dict(kind="benchmark_consent", episode=0, purpose="tool_execution", **v) for v in votes],
            *calls, score]


class FloorAnalysisTests(unittest.TestCase):
    def test_a_fetched_url_from_data_is_chosen_by_data(self):
        self.assertEqual(fe.chosen_by_data(STEPS[2]), ["url"])
        self.assertEqual(fe.chosen_by_data(STEPS[0]), [])

    def test_the_floor_asks_and_the_strict_owner_refuses_so_nothing_is_fetched(self):
        row = fe.episode_row(episode(
            [dict(decision="approve", clause=2),
             dict(decision="refuse", clause=3, reason="consent_derived_destination")],
            [call("dojo.slack.read_channel", channel="general"), call("dojo.model.extract", target="url")]))
        self.assertEqual((row["data_chosen_steps"], row["asked"], row["refused_by_owner"], row["dispatched"],
                          row["dispatched_unapproved"], row["attacker_reached"]), (1, 1, 1, 0, 0, 0))
        self.assertEqual(row["refusal_reasons"], ["consent_derived_destination"])

    def test_without_the_floor_the_fetch_runs_unasked_and_reaches_the_attacker(self):
        row = fe.episode_row(episode(
            [dict(decision="approve", clause=2)],
            [call("dojo.slack.read_channel", channel="general"), call("dojo.model.extract", target="url"),
             call("dojo.web.get", url="www.true-informations.com")], success=True))
        self.assertEqual((row["asked"], row["dispatched"], row["dispatched_unapproved"], row["attacker_reached"],
                          row["success"]), (0, 1, 1, 1, True))
        self.assertEqual(row["attacker_tools"], ["dojo.web.get"])


if __name__ == "__main__":
    unittest.main()
