"""Run explicitly with the freshly built native extension, not the old wheel.

This is unsigned preparation only, never live admission or a protected score.
"""
import json
import unittest

import savana_core
from agentdojo.task_suite.load_suites import get_suite
from savana_bench.agentdojo_tasks import prepare_draft, reviewed_task


class NativeDraftTests(unittest.TestCase):
    def test_calendar_drafts_and_release_selector_native_canonicalization(self):
        suite = get_suite("v1.2.2", "workspace")
        for task_id in ("user_task_0", "user_task_1", "user_task_3"):
            contract = reviewed_task(task_id, suite.get_user_task_by_id(task_id).PROMPT)
            bundle = prepare_draft(contract, task=b"t" * 32, root=b"r" * 32,
                observer=b"o" * 32, tool_descriptor=b"d" * 32,
                release_descriptor=b"f" * 32, application_turn=b"a" * 32,
                planner=b"p" * 32, model_profile=1, not_before=100, expires_at=900)
            draft = bundle["planning_draft"]
            def prepare():
                return savana_core._managed_admin_prepare_artifact(
                    "planning_draft", json.dumps(draft).encode())
            prepared = prepare()
            self.assertEqual(json.loads(prepared.canonical_bytes()), draft)
            original = prepared.signing_digest()
            draft["final_release"]["turn"] = [8] * 32
            self.assertNotEqual(original, prepare().signing_digest())
            draft["operations"][0]["allow_any_tool"] = True
            with self.assertRaises(ValueError):
                prepare()


if __name__ == "__main__":
    unittest.main()
