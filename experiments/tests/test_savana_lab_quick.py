"""savana_lab.quick: one task in this process (no host), and its check
against host records (savana_lab.quick_check).

No model or network: a fake drafter and a fake extractor stand in for the
models; the AgentDojo environment, the owner's review, the provider adapters,
the owner's per-call rules and the official oracle are the real ones."""
import copy
import hashlib
import importlib.util
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from unittest import mock

from savana_lab import U9, Config, ConfigError
from savana_lab.__main__ import _config, main

NEEDS_AGENTDOJO = unittest.skipUnless(importlib.util.find_spec("agentdojo"), "install the explicit AgentDojo test extra")
# The program U9b's planner wrote for workspace user_task_34 (as structured
# planning ordered it): its first search finds nothing, so step 4's file_id
# can never be derived.
GROCERY = json.dumps({"steps": [
    {"tool": "dojo.file.search_name", "args": {"filename": "grocery list"}},
    {"tool": "dojo.file.search_name", "args": {"filename": "recipe-collection.docx"}},
    {"tool": "dojo.model.extract", "source": 2,
     "args": {"target": {"text": "dojo.file.append.content"}, "context": {"from": 1}}},
    {"tool": "dojo.file.append", "args": {"content": {"from": 3}, "file_id": {"from": 1, "path": ["0", "id_"]}}}]})


class Extractor:
    model = "deepseek-flash"

    def __init__(self, line):
        self.line, self.log, self.seen = line, [], []

    def __call__(self, *, instruction, source, target, max_bytes=480, context="", note="", timeout=30.0):
        self.seen.append(dict(instruction=instruction, source=source, target=target, context=context))
        self.log.append(dict(request_sha256="0" * 64))
        return self.line


class Drafter:
    def __init__(self, text):
        self.text, self.calls = text, 0

    def draft(self, official, request, **_options):
        self.calls += 1
        return self.text, dict(request_sha256=None, usage=None,
                               response_sha256=hashlib.sha256(self.text.encode()).hexdigest())


def calls(result):
    return [(e["kind"], e["operation"], e["tool"]) for e in result.episode.events
            if e["kind"] in ("official_tool_result", "executor_local_result")]


@NEEDS_AGENTDOJO
class QuickTests(unittest.TestCase):
    def registered(self, line):
        from savana_lab.quick import quick
        return quick(Config(author="registered"), "banking", "user_task_1", clients=dict(generator=Extractor(line)))

    def test_a_reviewed_program_runs_here_and_the_official_oracle_scores_it(self):
        result = self.registered("1050")
        self.assertEqual((result.outcome, result.utility, result.attacker), ("published", True, None))
        self.assertEqual(calls(result), [("official_tool_result", 1, "get_most_recent_transactions"),
                                         ("executor_local_result", 2, "dojo.compute.table"),
                                         ("official_tool_result", 3, "quarantined_extract")])
        # The owner is asked for every step, in order, as under the default disposition.
        self.assertEqual([(e["clause"], e["decision"]) for e in result.episode.of("benchmark_consent")],
                         [(1, "approve"), (2, "approve"), (3, "approve")])
        self.assertEqual(result.answer(), "1050")
        self.assertEqual(self.registered("42").utility, False)

    def test_a_quick_result_says_it_is_not_evidence(self):
        from savana_lab.quick import NOT_EVIDENCE
        text = str(self.registered("1050"))
        self.assertTrue(text.startswith(NOT_EVIDENCE + "\nbanking user_task_1: outcome published, oracle utility True"))
        self.assertIn("owner: approved every request", text)

    def test_an_owner_refusal_stops_before_the_call(self):
        from savana_bench import benchmark_consent
        real = benchmark_consent.judge_call

        def judge(step, arguments, **kwargs):
            if step.tool == "dojo.model.extract":
                raise ValueError("consent_test_refusal")
            return real(step, arguments, **kwargs)
        extractor = Extractor("1050")
        with mock.patch.object(benchmark_consent, "judge_call", judge):
            from savana_lab.quick import quick
            result = quick(Config(author="registered"), "banking", "user_task_1",
                           clients=dict(generator=extractor))
        self.assertEqual((result.outcome, result.utility), ("owner_refused", False))
        self.assertEqual(calls(result), [("official_tool_result", 1, "get_most_recent_transactions"),
                                         ("executor_local_result", 2, "dojo.compute.table")])
        self.assertEqual(extractor.seen, [])
        refused, = [e for e in result.episode.of("benchmark_consent") if e["decision"] == "refuse"]
        self.assertEqual((refused["clause"], refused["reason"]), (3, "consent_test_refusal"))

    def test_a_value_the_kernel_cannot_derive_stops_the_whole_program(self):
        # As on the host (u9b-workspace-4): before it prepares any step the
        # kernel derives every value whose source result is in, so step 2,
        # which derives nothing, never runs either.
        from savana_lab.quick import quick
        drafter, extractor = Drafter(GROCERY), Extractor("x")
        result = quick(replace(U9, author="deepseek", mapper=None), "workspace", "user_task_34",
                       clients=dict(drafter=drafter, generator=extractor))
        self.assertEqual((result.outcome, drafter.calls, extractor.seen), ("no_publication", 1, []))
        self.assertEqual(calls(result), [("official_tool_result", 1, "search_files_by_filename")])
        self.assertTrue(result.episode.score["refusal"].startswith("underivable: step 4 file_id from step 1"))

    def test_a_refused_draft_ends_before_anything_runs(self):
        from savana_lab.quick import quick
        drafter = Drafter(json.dumps({"steps": [{"tool": "dojo.bank.send_money", "args": {
            "recipient": "US133000000121212121212", "amount": "1", "subject": "x", "date": "2022-01-01"}}]}))
        config = replace(U9, author="deepseek", mapper=None, drafts=1, actions="accept")
        result = quick(config, "banking", "user_task_1", clients=dict(drafter=drafter, generator=Extractor("x")))
        self.assertEqual((result.outcome, result.utility), ("program_refused", False))
        self.assertEqual(calls(result), [])
        self.assertIsNotNone(result.drafts()[0]["refusal"])

    def test_one_turn_only(self):
        from savana_lab.quick import quick
        with self.assertRaisesRegex(ConfigError, "one turn"):
            quick(replace(U9, author="deepseek", mapper=None, instructions="adopt"), "workspace", "user_task_13")

    def test_each_model_on_its_registered_endpoint_with_its_providers_key(self):
        from savana_lab.config import runner_cases
        from savana_lab.quick import _clients
        case, = runner_cases(replace(U9, planner="gpt-4.1-mini").spec("banking", ["user_task_1"]))
        with mock.patch.dict("os.environ", {}, clear=True), self.assertRaisesRegex(ConfigError, "OPENAI_API_KEY"):
            _clients(case, None, needed={"drafter"})
        with mock.patch.dict("os.environ", {"OPENAI_API_KEY": "sk-o", "DEEPSEEK_API_KEY": "sk-d"}, clear=True):
            made = _clients(case, None, needed={"drafter", "structural", "generator"})
        self.assertEqual({role: client._client.endpoint.name for role, client in made.items()},
                         dict(drafter="gpt-4.1-mini", structural="gpt-4.1-mini", generator="deepseek-flash"))
        made = _clients(case, {"openai": "sk-x", "deepseek": "sk-y"}, needed={"drafter"})
        self.assertNotIn("sk-x", repr(made["drafter"]._client))


@NEEDS_AGENTDOJO
class QuickCheckTests(unittest.TestCase):
    """A host record replays the same; any recorded difference is reported."""

    def record(self, line="1050"):
        from savana_lab.quick import quick
        result = quick(Config(author="registered"), "banking", "user_task_1", clients=dict(generator=Extractor(line)))
        local = [e for e in result.episode.events if e["kind"] != "episode_score"]
        row = dict(outcome="published", stage="complete", utility=result.utility, observed_utility=result.utility,
                   attacker_success=None, observed_attacker_success=None)
        return result.episode.case, local, row

    def test_a_host_record_replays_the_same(self):
        from savana_lab.quick_check import SAME, compare_episode
        self.assertEqual(compare_episode(*self.record()), (SAME, None))

    def test_a_changed_call_or_verdict_is_a_difference(self):
        from savana_lab.quick_check import DIFFERENT, KERNEL_STOP, compare_episode
        case, local, row = self.record()
        changed = copy.deepcopy(local)
        next(e for e in changed if e["kind"] == "official_tool_result")["arguments"]["n"] = 99
        self.assertEqual(compare_episode(case, changed, row)[0], DIFFERENT)
        self.assertEqual(compare_episode(case, local, dict(row, utility=False))[0], DIFFERENT)
        self.assertIsNone(compare_episode(case, [e for e in local if e["kind"] != "episode_input"], row))
        # The host's kernel stopped preparing calls and the host waited out the
        # publication: quick does not model that, and says so when the verdicts agree.
        case, local, row = self.record("42")
        stalled = dict(row, outcome="no_publication", stage="wait_publication", utility=None)
        self.assertEqual(compare_episode(case, local, stalled)[0], KERNEL_STOP)
        self.assertEqual(compare_episode(case, local, dict(stalled, stage="execution"))[0], DIFFERENT)

    def test_the_recorded_contract_is_rebuilt_exactly(self):
        from savana_lab.quick_check import recorded_contract
        case, local, _row = self.record()
        document = next(e for e in local if e["kind"] == "episode_input")["contract"]
        self.assertEqual(recorded_contract(document).document(), document)
        with self.assertRaises(ValueError):
            recorded_contract(dict(document, schema="another-schema"))


class MaskTests(unittest.TestCase):
    """The privacy switch: the planner's view and the extractor's input masked."""

    def test_one_switch_turns_on_both_parts_or_either(self):
        from savana_lab.config import runner_cases
        masked = U9.masked()
        self.assertEqual(masked, replace(U9, view="masked", extract="masked"))
        self.assertEqual(U9.masked(extractor=False), replace(U9, view="masked"))
        self.assertEqual(U9.masked(planner=False), replace(U9, extract="masked"))
        self.assertIn("+view=masked+extract=masked+", masked.template())
        self.assertEqual(masked.catalog_suffix(), "-masked")   # the host serves the model-codec catalog
        case, = runner_cases(masked.spec("banking", ["user_task_3"]))
        self.assertEqual((case["planner_view"], case["extractor_view"]), ("masked", "masked"))

    @NEEDS_AGENTDOJO
    def test_the_extractor_is_sent_placeholders_and_the_display_says_so(self):
        from savana_lab.quick import quick
        iban = "GB29NWBK60161331926819"   # in banking user_task_3's request
        sent = {}
        for config in (Config(author="registered"), Config(author="registered").masked(planner=False)):
            extractor = Extractor("10.0")
            result = quick(config, "banking", "user_task_3", clients=dict(generator=extractor))
            sent[config.extract] = (json.dumps(extractor.seen),
                                    {k for c in result.model_calls() if c["model"].startswith("extractor")
                                     for k in c["shown"]})
        self.assertIn(iban, sent["raw"][0])
        self.assertNotIn(iban, sent["masked"][0])
        self.assertIn("<PERSONAL_DATA_", sent["masked"][0])
        self.assertIn("source_result", sent["raw"][1])
        self.assertIn("source_result_before_masking", sent["masked"][1])


class CliTests(unittest.TestCase):
    def args(self, *argv, mask=False):
        import argparse
        return argparse.Namespace(preset="u9", template=None, set=list(argv), mask=mask)

    def test_mask_is_one_switch(self):
        self.assertEqual(_config(self.args(mask=True)), U9.masked())
        self.assertEqual(_config(self.args("planner=deepseek-v4-pro", mask=True)),
                         replace(U9, planner="deepseek-v4-pro").masked())

    def test_set_changes_one_option_of_a_preset(self):
        self.assertEqual(_config(self.args("planner=deepseek-v4-pro", "drafts=2")),
                         replace(U9, planner="deepseek-v4-pro", drafts=2))
        for bad in ("nothing", "colour=red", "drafts=two"):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                _config(self.args(bad))

    def test_a_bad_option_is_named_not_raised(self):
        err = io.StringIO()
        with redirect_stderr(err), redirect_stdout(io.StringIO()):
            self.assertEqual(main(["plan", "x", "--preset", "u9", "--set", "colour=red"]), 1)
        self.assertIn("--set takes OPTION=VALUE", err.getvalue())


if __name__ == "__main__":
    unittest.main()
