"""Review-feedback retry for planner-drafted programs: the refusal location,
the exact planner input (pure, recomputable), the fixed hints, the spec, and
the offline verifier's replay of every draft. Never kernel or model evidence."""
import hashlib
import json
import re
from pathlib import Path
import unittest

from agentdojo.task_suite.load_suites import get_suite
from savana_bench.drafted_tasks import ProgramRefused, parse_program_text, review_program
from savana_bench.dojo_catalog import SUITE_TOOLS
from savana_bench.planner_experiment import MAX_DRAFTS, PLANNER_MODELS, experiment_cases
from savana_bench.planner_verify import _drafted_contract
from savana_bench.root_drafter import (REFUSAL_HINTS, ROOT_SYSTEM, draft_request_body, planner_catalog,
                                       poisoned_root_system, refusal_message)

SUITE, USER = "banking", "user_task_7"
GOOD = json.dumps({"steps": [{"tool": "dojo.bank.recent", "args": {"n": 50}},
                             {"tool": "dojo.model.extract", "source": 1,
                              "args": {"target": {"text": "answer"}, "context": {"from": 1}}}]})
BAD = json.dumps({"steps": [{"tool": "dojo.bank.recent", "args": {"n": 50}},
                            {"tool": "dojo.model.extract", "source": 1,
                             "args": {"target": {"text": "answer"}, "context": {"text": "x"}}}]})


def _suite():
    return get_suite("v1.2.2", SUITE)


def _review(text):
    official = _suite()
    return review_program(suite=SUITE, suite_tools=SUITE_TOOLS[SUITE], task_id=USER,
                          prompt=official.get_user_task_by_id(USER).PROMPT, program=parse_program_text(text))


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _events(texts, *, model=PLANNER_MODELS[0], goal=None):
    """The evidence an honest runner records for these consecutive drafts."""
    official = _suite()
    prompt = official.get_user_task_by_id(USER).PROMPT
    events, history = [], []
    for attempt, text in enumerate(texts, 1):
        body = draft_request_body(official, prompt, model=model, goal=goal, history=tuple(history))
        events.append(dict(kind="root_drafted", attempt=attempt, program_text=text,
                           request_sha256=_sha(body), response_sha256=_sha(text.encode())))
        try:
            _review(text)
        except ProgramRefused as error:
            events.append(dict(kind="program_refused", attempt=attempt, reason=str(error),
                               step=error.step, field=error.field))
            history.append((text, str(error), error.step, error.field))
    return events


def _case(max_drafts=3, model=PLANNER_MODELS[0], goal=None):
    return dict(suite=SUITE, user=USER, max_drafts=max_drafts, planner_model=model, goal=goal)


class RefusalLocationTests(unittest.TestCase):
    def test_refusal_carries_step_and_field_and_keeps_its_code(self):
        with self.assertRaises(ProgramRefused) as caught:
            _review(BAD)
        self.assertEqual((str(caught.exception), caught.exception.step, caught.exception.field),
                         ("extract_context", 2, "context"))
        with self.assertRaises(ProgramRefused) as caught:
            parse_program_text("not json")
        self.assertEqual((str(caught.exception), caught.exception.step, caught.exception.field),
                         ("program_json", None, None))
        _review(GOOD)


class PlannerInputTests(unittest.TestCase):
    def test_first_draft_body_is_unchanged(self):
        # The honest single-draft request is byte-for-byte what it was before
        # retries existed, so earlier runs and this one draft identically.
        official = _suite()
        prompt = official.get_user_task_by_id(USER).PROMPT
        user = json.dumps(dict(request=prompt, tools=planner_catalog(official)), ensure_ascii=False)
        before = json.dumps(dict(model="deepseek-flash",
            messages=[dict(role="system", content=ROOT_SYSTEM), dict(role="user", content=user)],
            temperature=0, max_tokens=2048, thinking={"type": "disabled"}, stream=False,
            response_format={"type": "json_object"}), ensure_ascii=False, allow_nan=False).encode()
        self.assertEqual(draft_request_body(official, prompt, model="deepseek-flash"), before)

    def test_retry_adds_only_the_own_program_and_a_fixed_message(self):
        official = _suite()
        prompt = official.get_user_task_by_id(USER).PROMPT
        body = json.loads(draft_request_body(official, prompt, model="deepseek-flash",
                                             history=((BAD, "extract_context", 2, "context"),)))
        self.assertEqual([m["role"] for m in body["messages"]], ["system", "user", "assistant", "user"])
        self.assertEqual(body["messages"][2]["content"], BAD)
        self.assertEqual(body["messages"][3]["content"], refusal_message("extract_context", 2, "context"))
        poisoned = json.loads(draft_request_body(official, prompt, model="deepseek-flash", goal="exfiltrate"))
        self.assertEqual(poisoned["messages"][0]["content"], poisoned_root_system("exfiltrate"))

    def test_every_review_code_has_a_fixed_hint(self):
        source = (Path(__file__).parents[1] / "savana_bench" / "drafted_tasks.py").read_text()
        codes = set(re.findall(r'(?:_refuse|ProgramRefused)\("([a-z_]+)"\)', source))
        self.assertTrue(codes)
        self.assertEqual(codes - set(REFUSAL_HINTS), set())
        message = refusal_message("edge_path", 3, "file_id")
        self.assertIn("edge_path at step 3, field file_id.", message)
        self.assertIn(REFUSAL_HINTS["edge_path"], message)


class SpecTests(unittest.TestCase):
    def test_drafts_and_planner_options(self):
        default, = experiment_cases("drafted:banking:user_task_7")
        self.assertEqual((default["max_drafts"], default["planner_model"]), (1, "deepseek-flash"))
        retry, = experiment_cases("drafted+drafts=3:banking:user_task_7")
        self.assertEqual((retry["max_drafts"], retry["group"]), (3, "drafted_benign"))
        strong, = experiment_cases("drafted+drafts=3+planner=deepseek-v4-pro:banking:user_task_7")
        self.assertEqual((strong["max_drafts"], strong["planner_model"]), (3, "deepseek-v4-pro"))
        poison, = experiment_cases("drafted-poison+drafts=2:tamper:banking:user_task_7")
        self.assertEqual((poison["goal"], poison["max_drafts"], poison["group"]), ("tamper", 2, "drafted_poisoned"))
        for bad in ("drafted+drafts=0:banking:user_task_7", f"drafted+drafts={MAX_DRAFTS + 1}:banking:user_task_7",
                    "drafted+drafts=3+drafts=2:banking:user_task_7", "drafted+planner=gpt:banking:user_task_7",
                    "drafted+retry=3:banking:user_task_7", "drafted+drafts:banking:user_task_7",
                    "draftedx:banking:user_task_7"):
            with self.assertRaises(ValueError, msg=bad):
                experiment_cases(bad)


class VerifierReplayTests(unittest.TestCase):
    def test_refused_then_accepted(self):
        events = _events([BAD, GOOD])
        contract = _drafted_contract(_case(), events, dict(outcome="published", drafts=2))
        self.assertIsNotNone(contract)

    def test_all_refused_up_to_the_limit(self):
        events = _events([BAD, BAD])
        self.assertIsNone(_drafted_contract(_case(max_drafts=2), events,
                                            dict(outcome="program_refused", refusal="extract_context", drafts=2)))
        with self.assertRaises(ValueError):  # refused before the limit was used up
            _drafted_contract(_case(max_drafts=3), events,
                              dict(outcome="program_refused", refusal="extract_context", drafts=2))

    def test_the_planner_input_is_recomputed(self):
        events = _events([BAD, GOOD])
        events[2] = dict(events[2], request_sha256="00" * 32)  # the harness sent something else
        with self.assertRaisesRegex(ValueError, "planner_input_mismatch"):
            _drafted_contract(_case(), events, dict(outcome="published", drafts=2))
        events = _events([BAD, GOOD], model="deepseek-v4-pro")
        with self.assertRaisesRegex(ValueError, "planner_input_mismatch"):  # recorded under another model
            _drafted_contract(_case(model="deepseek-flash"), events, dict(outcome="published", drafts=2))
        _drafted_contract(_case(model="deepseek-v4-pro"), events, dict(outcome="published", drafts=2))

    def test_refusal_record_and_order_are_checked(self):
        events = _events([BAD, GOOD])
        moved = [dict(e, step=1) if e["kind"] == "program_refused" else e for e in events]
        with self.assertRaisesRegex(ValueError, "program_refusal_mismatch"):
            _drafted_contract(_case(), moved, dict(outcome="published", drafts=2))
        accepted_then_more = _events([GOOD, GOOD])
        with self.assertRaisesRegex(ValueError, "accepted_program_was_redrafted"):
            _drafted_contract(_case(), accepted_then_more, dict(outcome="published", drafts=2))
        with self.assertRaisesRegex(ValueError, "draft_count_row"):
            _drafted_contract(_case(), events, dict(outcome="published", drafts=1))

    def test_drafter_failure_after_a_refusal(self):
        events = _events([BAD])
        self.assertIsNone(_drafted_contract(_case(), events, dict(outcome="author_failed", drafts=1)))
        with self.assertRaisesRegex(ValueError, "drafter_failure_with_program"):
            _drafted_contract(_case(max_drafts=1), events, dict(outcome="author_failed", drafts=1))


if __name__ == "__main__":
    unittest.main()
