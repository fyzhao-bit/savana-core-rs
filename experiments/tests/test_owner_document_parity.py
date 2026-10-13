"""The owner document the harness commits, judged by the kernel's own check
(`FusedInputDocumentV04::check_owner_text_origin`, through the Rust example
`owner_document_check`): every program the owner's review admits, the
registered templates and the fixed programs among them, must be admitted by
the kernel too, input by input, and a document the review would never write
must be refused. Skipped unless the example is built:

    cargo build -p savana-policy-core --example owner_document_check
"""
import json
import os
from pathlib import Path
import subprocess
import unittest

from agentdojo.task_suite.load_suites import get_suite
from savana_bench.agentdojo_tasks import catalog_tool, owner_document, owner_inputs, register_drafted
from savana_bench.drafted_tasks import parse_program_text, review_program

ROOT = Path(__file__).resolve().parents[2]


def checker():
    named = os.environ.get("SAVANA_OWNER_DOCUMENT_CHECK")
    if named:
        return Path(named)
    for profile in ("debug", "release"):
        path = ROOT / "target" / profile / "examples" / "owner_document_check"
        if path.is_file():
            return path
    return None


def case(contract, document=None):
    """One checker case: the document and where the plan puts each input."""
    steps = contract.steps()
    uses = []
    for row in owner_inputs(contract):
        tool = steps[row.get("operation", 1) - 1].tool
        field, = [f for f in catalog_tool(tool)["fields"] if f["name"] == row["argument"]]
        uses.append(dict(slot=row["slot"], operation=tool, **field))
    return dict(document=owner_document(contract) if document is None else document, uses=uses)


def verdicts(cases):
    lines = "".join(json.dumps(c) + "\n" for c in cases)
    out = subprocess.run([str(checker())], input=lines, capture_output=True, text=True, check=True, timeout=600)
    return out.stdout.splitlines()


def admitted_programs():
    """(suite, user, contract) for every registered template and fixed program."""
    from savana_bench.fixed_programs import FIXED_PROGRAMS, fixed_program_text
    from savana_bench.structured_templates import load_registry
    suites, found = {}, []

    def review(suite, user, program, **options):
        official = suites.setdefault(suite, get_suite("v1.2.2", suite))
        return register_drafted(review_program(
            suite=suite, suite_tools={t.name for t in official.tools}, task_id=user,
            prompt=official.get_user_task_by_id(user).PROMPT, program=program, **options))
    for item in load_registry()["templates"]:
        found.append((item["suite"], item["user"], review(item["suite"], item["user"], item["program"])))
    for (suite, user) in FIXED_PROGRAMS:
        program = parse_program_text(fixed_program_text(suite, user))
        found.append((suite, user, review(suite, user, program, derived_destinations=True)))
    return found


@unittest.skipUnless(checker(), "build the owner_document_check example")
class OwnerDocumentParityTests(unittest.TestCase):
    def test_every_admitted_program_is_admitted_by_the_kernel(self):
        programs = admitted_programs()
        self.assertGreaterEqual(len(programs), 80)
        results = verdicts([case(contract) for _suite, _user, contract in programs])
        refused = [(suite, user, verdict) for (suite, user, _c), verdict in zip(programs, results) if verdict != "ok"]
        self.assertEqual(refused, [])

    def test_a_document_the_review_would_not_write_is_refused(self):
        suite, user, contract = next(p for p in admitted_programs()
                                     if any(r["text"] for r in owner_inputs(p[2]) if not r["text"].isspace()))
        document = json.loads(owner_document(contract))
        cases = []
        # A constant the document binds elsewhere, then a constant bound nowhere.
        if document["constants"]:
            moved = json.loads(json.dumps(document))
            for constant in moved["constants"]:
                for place in constant["fields"]:
                    place["field"] = place["field"] + "_elsewhere"
            cases.append(json.dumps(moved, sort_keys=True, separators=(",", ":")))
        stripped = dict(document, constants=[])
        cases.append(json.dumps(stripped, sort_keys=True, separators=(",", ":")))
        results = verdicts([case(contract, text) for text in cases])
        self.assertTrue(all(v.startswith("refused") for v in results), (suite, user, results))


if __name__ == "__main__":
    unittest.main()
