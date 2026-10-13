"""One extraction that produces several fields of one operation (U3): the
review, the adapter's reply rule and the edge paths, end to end through the
reviewed provider with a fake extractor in place of the model."""
import hashlib
import importlib.util
import unittest
from types import SimpleNamespace

from savana_bench.agentdojo_provider import canonical
from savana_bench.agentdojo_tasks import edge_parts, expected_step_call, register_drafted, select_result_path
from savana_bench.drafted_tasks import MULTI_PREFIX, ProgramRefused, extracted_fields
from savana_bench.dojo_provider import ANSWER_BYTES, dojo_provider, target_description, target_kind
from tests.test_drafted_tasks import BINDING, decode, review, suite_and_task

NEEDS_AGENTDOJO = unittest.skipUnless(importlib.util.find_spec("agentdojo"), "install the explicit AgentDojo test extra")

RECIPIENT = "GB29NWBK60161331926819"
FIELDS = ["send_money.amount", "send_money.subject", "send_money.date"]


def refund(target=FIELDS, **overrides):
    """banking user_task_4: read, ONE extraction of three fields, then the refund."""
    pay = {"recipient": {"text": RECIPIENT}, "amount": {"from": 2, "path": ["amount"]},
           "subject": {"from": 2, "path": ["subject"]}, "date": {"from": 2, "path": ["date"]}}
    pay.update(overrides)
    return {"steps": [{"tool": "dojo.bank.recent", "args": {"n": 50}},
                      {"tool": "dojo.model.extract", "source": 1, "args": {"target": {"text": target}}},
                      {"tool": "dojo.bank.send_money", "args": pay}]}


def refused(program):
    with self_check() as caught:
        review("banking", "user_task_4", program)
    return str(caught.exception), caught.exception.field


class self_check:
    def __enter__(self):
        self.exception = None
        return self

    def __exit__(self, kind, value, _traceback):
        if kind is not ProgramRefused:
            raise AssertionError(f"expected ProgramRefused, got {kind}")
        self.exception = value
        return True


@NEEDS_AGENTDOJO
class ReviewTests(unittest.TestCase):
    def test_one_extraction_signs_three_named_edges(self):
        contract = review("banking", "user_task_4", refund())
        extraction, pay = contract.steps()[1], contract.steps()[2]
        self.assertEqual(extracted_fields(extraction), ("amount", "subject", "date"))
        self.assertEqual(extraction.value_map()["target"],
                         "dojo.bank.send_money.amount; dojo.bank.send_money.subject; dojo.bank.send_money.date")
        paths = {edge_parts(edge)[0]: edge_parts(edge)[2] for edge in pay.derived}
        self.assertEqual(paths, {name: MULTI_PREFIX + (name,) for name in ("amount", "subject", "date")})
        self.assertEqual(pay.value_map()["recipient"], RECIPIENT)

    def test_each_field_is_taken_by_its_own_name(self):
        self.assertEqual(refused(refund(amount={"from": 2})), ("edge_path", "amount"))
        self.assertEqual(refused(refund(amount={"from": 2, "path": ["recipient"]})), ("edge_path", "amount"))
        self.assertEqual(refused(refund(amount={"from": 2, "path": ["amount", "x"]})), ("edge_path", "amount"))
        self.assertEqual(refused(refund(amount={"from": 2, "path": ["dojo.bank.send_money.recipient"]})),
                         ("edge_path", "amount"))
        self.assertEqual(refused(refund(amount={"from": 2, "path": ["money.amount"]})), ("edge_path", "amount"))

    def test_a_field_may_be_named_by_its_target_label(self):
        # Planners take a field by the label they wrote in the target; the
        # signed edge names the field either way.
        by_name = review("banking", "user_task_4", refund())
        for label in ("dojo.bank.send_money.amount", "send_money.amount"):
            contract = review("banking", "user_task_4", refund(amount={"from": 2, "path": [label]}))
            self.assertEqual(contract.steps()[2].derived, by_name.steps()[2].derived, label)

    def test_the_target_is_two_to_four_fields_of_one_operation(self):
        for target in (["send_money.amount"], FIELDS + ["send_money.recipient", "schedule.amount"],
                       ["send_money.amount", "schedule.amount"], ["send_money.amount", "answer"],
                       ["send_money.amount", "send_money.amount"], ["send_money.amount", "nonsense"],
                       ["send_money.amount", 7]):
            self.assertEqual(refused(refund(target=target))[0], "extract_target", target)

    def test_a_multi_field_result_never_feeds_a_compute_table(self):
        program = refund()
        program["steps"].insert(2, {"tool": "dojo.compute.table", "args": {"input1": {"from": 2}, "output": "count"}})
        program["steps"][3]["args"].update({k: {"from": 2, "path": [k]} for k in ("amount", "subject", "date")})
        self.assertEqual(refused(program)[0], "compute_input")


@NEEDS_AGENTDOJO
class AdapterTests(unittest.TestCase):
    def test_the_reply_is_one_object_with_exactly_the_fields(self):
        target = "; ".join("dojo.bank." + f for f in FIELDS)
        self.assertEqual(target_kind(target), "multi")
        suite, _task = suite_and_task("banking", "user_task_4")
        functions = {f.name: f for f in suite.tools}
        description, bound = target_description(target, functions)
        self.assertEqual(bound, ANSWER_BYTES)
        for name in ('"amount"', '"subject"', '"date"'):
            self.assertIn(name, description)

    def run_refund(self, reply):
        suite, task = suite_and_task("banking", "user_task_4")
        contract = register_drafted(review("banking", "user_task_4", refund()))
        env = task.init_environment(suite.load_and_inject_default_environment({}))
        provider = dojo_provider(suite, env, max_calls=3, generator=lambda **_kw: reply)
        from savana_bench.protected_endpoint import EpisodeEndpoint
        endpoint = EpisodeEndpoint(contract=contract, provider=provider, binding=BINDING, tool_url="https://tool/",
                                   release_url="https://release/", emit=lambda kind, **data: None)
        results = []
        for number in range(3):
            params = expected_step_call(contract, number, results)
            payload = canonical({"jsonrpc": "2.0", "id": f"s{number}", "method": "tools/call", "params": params})
            frame = SimpleNamespace(nonce=bytes([number + 1]) * 32, wire_digest=hashlib.sha256(payload).digest(),
                                    core=b"c" * 32, subject=b"s" * 32, url="https://tool/", pin=b"p" * 32,
                                    payload=payload)
            results.append(endpoint.exchange(frame))
            if decode(results[-1])["result"]["structuredContent"]["savana_status"] != "succeeded":
                return env, results
        return env, results

    def test_each_value_reaches_its_own_field(self):
        env, results = self.run_refund('{"amount": 10, "subject": " Refund  for dinner ", "date": "2022-04-01"}')
        self.assertEqual(len(results), 3)
        self.assertEqual(select_result_path(results[1], MULTI_PREFIX + ("subject",)), "Refund for dinner")
        sent = env.bank_account.transactions[-1]
        self.assertEqual((sent.recipient, sent.amount, sent.subject, sent.date),
                         (RECIPIENT, 10.0, "Refund for dinner", "2022-04-01"))

    def test_any_other_reply_fails_the_step(self):
        for reply in ("10, Refund, 2022-04-01", '{"amount": "10", "subject": "Refund"}',
                      '{"amount": "10", "subject": "Refund", "date": "2022-04-01", "recipient": "X"}',
                      '{"amount": true, "subject": "Refund", "date": "2022-04-01"}', '["10", "Refund", "2022-04-01"]'):
            # The extraction's outcome is unknown: the episode stops, nothing is paid.
            with self.assertRaisesRegex(ValueError, "official_tool_outcome_unknown", msg=reply):
                self.run_refund(reply)


if __name__ == "__main__":
    unittest.main()
