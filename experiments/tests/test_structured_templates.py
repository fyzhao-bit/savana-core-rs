"""Registered templates for the structured-planning evaluation: the current
owner review replayed over hash-chained draft logs, and the committed
registry. Never kernel, model or benchmark evidence."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from agentdojo.task_suite.load_suites import get_suite
from savana_bench.agentdojo_provider import canonical
from savana_bench.drafted_tasks import parse_program_text, review_program
from savana_bench.protected_agentdojo import ResearchAudit
from savana_bench.structured_templates import REGISTRY, build, encode_registry, load_registry, summary, template

SUITE, USER = "banking", "user_task_7"
GOOD = json.dumps({"steps": [{"tool": "dojo.bank.recent", "args": {"n": 50}},
                             {"tool": "dojo.model.extract", "source": 1,
                              "args": {"target": {"text": "answer"}, "context": {"from": 1}}}]})
BAD = json.dumps({"steps": [{"tool": "dojo.bank.recent", "args": {"n": 50}},
                            {"tool": "dojo.model.extract", "source": 1,
                             "args": {"target": {"text": "answer"}, "context": {"text": "x"}}}]})
DEST = json.dumps({"steps": [{"tool": "dojo.bank.recent", "args": {"n": 50}},
                             {"tool": "dojo.bank.send_money", "args": {
                                 "amount": {"from": 1, "path": ["0", "amount"]},
                                 "date": {"from": 1, "path": ["0", "date"]},
                                 "recipient": {"from": 1, "path": ["0", "recipient"]},
                                 "subject": {"from": 1, "path": ["0", "subject"]}}}]})
CASE = dict(suite=SUITE, user=USER, root_author="deepseek", planner_view="request", planner_model="deepseek-flash",
            extractor_model="deepseek-flash", max_drafts=3)


def _batch(root, name, texts, *, tamper=False):
    """One hash-chained source run whose only episode drafted `texts`, with a
    score and an environment line the build must never use."""
    batch = root / name
    batch.mkdir()
    audit = ResearchAudit(batch / ("ab" * 16))
    audit.emit("manifest", cases=[CASE])
    for attempt, text in enumerate(texts, 1):
        audit.emit("root_drafted", episode=0, attempt=attempt, program_text=text,
                   response_sha256=hashlib.sha256(text.encode()).hexdigest())
    audit.emit("episode_input", episode=0, environment={"secret_balance": "SENTINEL_ENVIRONMENT"})
    audit.emit("episode_score", episode=0, utility="SENTINEL_UTILITY")
    audit.artifact("completion.json", dict(audit_head=audit.head, event_count=audit.count))
    audit.close()
    if tamper:
        path = audit.directory / "events.jsonl"
        path.write_bytes(path.read_bytes().replace(b"SENTINEL_UTILITY", b"SENTINEL_UTILITX"))
    return audit


class ReplayTests(unittest.TestCase):
    def test_first_accepted_draft_is_registered_unedited_with_its_source(self):
        with tempfile.TemporaryDirectory() as directory:
            audit = _batch(Path(directory), "g12k-banking-0", [BAD, GOOD])
            registry = build(directory)
        item, = registry["templates"]
        self.assertEqual(item["program"], parse_program_text(GOOD))
        self.assertEqual(item["program_sha256"], hashlib.sha256(canonical(item["program"])).hexdigest())
        self.assertEqual((item["source"]["attempt"], item["source"]["drafts"]), (2, 2))
        self.assertEqual(item["source"]["audit_head"], audit.head)
        self.assertEqual(item["source"]["program_text_sha256"], hashlib.sha256(GOOD.encode()).hexdigest())
        encoded = encode_registry(registry)
        self.assertNotIn(b"SENTINEL", encoded)
        self.assertEqual(summary(registry)["templates"], 1)

    def test_a_policy_refusal_ends_drafting_and_refused_tasks_have_none(self):
        with tempfile.TemporaryDirectory() as directory:
            _batch(Path(directory), "g12k-banking-0", [DEST, GOOD])
            registry = build(directory)
        self.assertEqual(registry["templates"], [])
        self.assertEqual(registry["excluded"], [dict(suite=SUITE, user=USER, drafts=2, reason="derived_destination")])
        with tempfile.TemporaryDirectory() as directory:
            _batch(Path(directory), "g12k-banking-0", [BAD])
            self.assertEqual(build(directory)["excluded"][0]["reason"], "extract_context")

    def test_a_broken_chain_or_completion_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            _batch(Path(directory), "g12k-banking-0", [GOOD], tamper=True)
            with self.assertRaisesRegex(ValueError, "broken_audit_chain"):
                build(directory)
        with tempfile.TemporaryDirectory() as directory:
            audit = _batch(Path(directory), "g12k-banking-0", [GOOD])
            (audit.directory / "completion.json").write_text(json.dumps(dict(audit_head="0" * 64, event_count=5)))
            with self.assertRaisesRegex(ValueError, "completion_digest_mismatch"):
                build(directory)


class RegistryTests(unittest.TestCase):
    def test_committed_registry_is_canonical_and_passes_the_current_review(self):
        registry = load_registry()
        self.assertEqual(REGISTRY.read_bytes(), encode_registry(registry))
        counts = summary(registry)
        self.assertEqual((counts["tasks"], counts["drafts"], counts["templates"]), (97, 137, 77))
        suites = {}
        for item in registry["templates"]:
            official = suites.setdefault(item["suite"], get_suite("v1.2.2", item["suite"]))
            contract = review_program(suite=item["suite"], suite_tools={t.name for t in official.tools},
                                      task_id=item["user"], prompt=official.get_user_task_by_id(item["user"]).PROMPT,
                                      program=item["program"])
            self.assertEqual(contract.digest(), item["contract_sha256"], item["user"])
            self.assertIs(template(registry, item["suite"], item["user"]), item)
        with self.assertRaises(KeyError):
            template(registry, "banking", "user_task_99")


if __name__ == "__main__":
    unittest.main()
