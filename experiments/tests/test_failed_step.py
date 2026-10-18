"""A call that does not come back succeeded ends its episode there
(`step_failed`), with the provider's closed reason, instead of a wait for a
publication that cannot come (the kernel keeps such a call Unknown and starts
nothing more for the task): the provider's code, the endpoint's record, the
runner's wait, the verifier's check of the record, quick mode's outcome, and
the extractor's empty reply."""
import asyncio
import hashlib
import importlib.util
import json
import time
import unittest
from dataclasses import replace
from types import SimpleNamespace

from savana_bench.agentdojo_provider import AgentDojoProvider, canonical, decode, error_code

NEEDS_AGENTDOJO = unittest.skipUnless(importlib.util.find_spec("agentdojo"), "install the explicit AgentDojo test extra")
NEEDS_SDK = unittest.skipUnless(importlib.util.find_spec("savana"), "install the savana SDK (crates/savana-core-py)")


def call(name, request_id="r-1", **arguments):
    return canonical({"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                      "params": {"name": name, "arguments": arguments}})


def status(reply):
    return decode(reply)["result"]["structuredContent"]["savana_status"]


class ErrorCodeTests(unittest.TestCase):
    def test_a_code_is_kept_and_free_text_never(self):
        self.assertEqual(error_code("ValueError: extract_fields"), "extract_fields")
        self.assertEqual(error_code("RuntimeError: upstream_failure"), "upstream_failure")
        self.assertEqual(error_code(ValueError("generator_output_empty")), "generator_output_empty")
        # A message that could carry data is replaced by its type alone.
        self.assertEqual(error_code("ValueError: Channel External_x not found"), "ValueError")
        self.assertEqual(error_code(KeyError("alice@example.org")), "KeyError")
        self.assertEqual(error_code(ValueError("a", "b")), "ValueError")
        self.assertEqual(error_code("no type here"), "unknown")


@NEEDS_AGENTDOJO
class ProviderTests(unittest.TestCase):
    def provider(self, function):
        from agentdojo.functions_runtime import FunctionsRuntime, make_function
        return AgentDojoProvider(FunctionsRuntime([make_function(function)]), None)

    def test_every_call_that_does_not_succeed_says_why(self):
        def extract(target: str):
            """Fails as the reviewed extractor does.

            :param target: The label.
            """
            raise ValueError("extract_fields" if target == "fields" else f"no value for {target}")
        provider = self.provider(extract)
        self.assertEqual(status(provider.exchange(call("extract", target="fields"))), "indeterminate")
        self.assertEqual(status(provider.exchange(call("extract", "r-2", target="alice@example.org"))),
                         "indeterminate")
        self.assertEqual(status(provider.exchange(call("other", "r-3", target="x"))), "failed")
        self.assertEqual(status(provider.exchange(call("extract", "r-4", target=7))), "failed")
        self.assertEqual([(row["status"], row["error"]) for row in provider.audit],
                         [("indeterminate", "extract_fields"), ("indeterminate", "ValueError"),
                          ("failed", "unknown_tool_or_argument"), ("failed", "invalid_arguments")])

    def test_a_succeeded_call_has_no_reason(self):
        def extract(target: str):
            """Answers.

            :param target: The label.
            """
            return {"text": target}
        provider = self.provider(extract)
        self.assertEqual(status(provider.exchange(call("extract", target="x"))), "succeeded")
        self.assertNotIn("error", provider.audit[0])


@NEEDS_AGENTDOJO
class EndpointTests(unittest.TestCase):
    def run_refund(self, reply):
        """banking user_task_4 (read, one extraction of three fields, the refund)
        with `reply` as the extractor's line: (endpoint, events, env)."""
        from savana_bench.agentdojo_tasks import expected_step_call, register_drafted
        from savana_bench.dojo_provider import dojo_provider
        from savana_bench.protected_endpoint import EpisodeEndpoint
        from tests.test_drafted_tasks import BINDING, review, suite_and_task
        from tests.test_multi_extraction import refund
        suite, task = suite_and_task("banking", "user_task_4")
        contract = register_drafted(review("banking", "user_task_4", refund()))
        env = task.init_environment(suite.load_and_inject_default_environment({}))
        provider = dojo_provider(suite, env, max_calls=3, generator=lambda **_kw: reply)
        events = []
        endpoint = EpisodeEndpoint(contract=contract, provider=provider, binding=BINDING, tool_url="https://tool/",
                                   release_url="https://release/",
                                   emit=lambda kind, **data: events.append(dict(kind=kind, **data)))
        results = []
        for number in range(3):
            params = expected_step_call(contract, number, results)
            payload = canonical({"jsonrpc": "2.0", "id": f"s{number}", "method": "tools/call", "params": params})
            frame = SimpleNamespace(nonce=bytes([number + 1]) * 32, wire_digest=hashlib.sha256(payload).digest(),
                                    core=b"c" * 32, subject=b"s" * 32, url="https://tool/", pin=b"p" * 32,
                                    payload=payload)
            try:
                results.append(endpoint.exchange(frame))
            except ValueError as error:
                self.assertEqual(str(error), "official_tool_outcome_unknown")
                # The endpoint is closed to anything after it.
                with self.assertRaisesRegex(ValueError, "episode_endpoint_closed"):
                    endpoint.exchange(frame)
                break
        return endpoint, events, env

    def test_an_extraction_the_adapter_refuses_is_recorded_with_its_reason(self):
        before = None
        for reply, error in (('{"amount": "10", "subject": "Refund"}', "extract_fields"),
                             ('{"amount": "10", "subject": " ", "date": "2022-04-01"}', "generator_output_empty")):
            endpoint, events, env = self.run_refund(reply)
            failed = dict(operation=2, tool="dojo.model.extract", status="indeterminate", error=error)
            self.assertEqual(endpoint.failed_step(), failed, reply)
            self.assertEqual([e for e in events if e["kind"] == "official_tool_failed"],
                             [dict(kind="official_tool_failed", **failed)])
            self.assertEqual([e["operation"] for e in events if e["kind"] == "official_tool_result"], [1])
            # Nothing was paid.
            count = len(env.bank_account.transactions)
            self.assertEqual(count, before if before is not None else count)
            before = count

    def test_a_step_that_succeeds_records_no_failure(self):
        endpoint, events, env = self.run_refund('{"amount": 10, "subject": "Refund", "date": "2022-04-01"}')
        self.assertIsNone(endpoint.failed_step())
        self.assertFalse([e for e in events if e["kind"] == "official_tool_failed"])
        self.assertEqual(env.bank_account.transactions[-1].subject, "Refund")


class FakeInner:
    """The native session's methods as the SDK's wait loop calls them: a run
    that never publishes and never asks for an approval."""
    def __init__(self):
        self.polls, self.closed = 0, False

    def poll_publication(self):
        self.polls += 1
        return None

    def poll_approval(self):
        return False

    def close(self):
        self.closed = True


@NEEDS_SDK
class WaitTests(unittest.TestCase):
    def finish(self, stopped, timeout):
        from savana.private_v04 import PrivateSession
        from savana_bench.private_episode import finish_private_episode
        inner, records = FakeInner(), []

        async def episode():
            session = PrivateSession._from_core(inner)

            async def receive(**_kw):
                raise AssertionError("nothing was published")
            return await finish_private_episode(
                session=session, expected_task=b"\x01" * 32, expected_run=b"\x02" * 32,
                expected_root=b"\x03" * 32, expected_destination=b"\x04" * 32, approval=lambda request: False,
                receive_publication=receive, emit=records.append, timeout=timeout, stopped=stopped)
        started = time.monotonic()
        outcome = asyncio.run(episode())
        return outcome, time.monotonic() - started, inner, records

    def test_the_wait_ends_once_the_run_can_no_longer_publish(self):
        at = time.monotonic() + 0.5
        outcome, seconds, inner, records = self.finish(lambda: time.monotonic() > at, timeout=30)
        self.assertLess(seconds, 5)
        self.assertEqual((outcome.status, outcome.stage, outcome.payload), ("unknown", "wait_publication", None))
        self.assertTrue(inner.closed)
        self.assertGreater(inner.polls, 0)
        self.assertEqual([r["kind"] for r in records], ["private_wait_started", "private_episode_observed"])
        self.assertEqual(records[-1]["status"], "unknown")

    def test_without_a_stop_it_waits_out_its_timeout(self):
        outcome, seconds, inner, _records = self.finish(lambda: None, timeout=1.0)
        self.assertGreaterEqual(seconds, 1.0)
        self.assertEqual((outcome.status, outcome.stage), ("unknown", "wait_publication"))
        self.assertTrue(inner.closed)

    def test_a_stop_signal_must_be_callable(self):
        with self.assertRaisesRegex(ValueError, "stop_signal_not_callable"):
            self.finish(True, timeout=1.0)


class VerifierTests(unittest.TestCase):
    FAILED = dict(operation=2, tool="dojo.model.extract", status="indeterminate", error="extract_fields")

    def local(self, *tail):
        return [dict(kind="provider_attempt"), dict(kind="official_tool_result", operation=1),
                dict(kind="provider_attempt"), dict(kind="official_tool_failed", episode=0, seq=9, **self.FAILED),
                *tail]

    def check(self, local, row):
        from savana_bench.planner_verify import _failed_step
        _failed_step(local, row)

    def test_a_failed_step_row_is_exactly_its_recorded_call(self):
        row = dict(outcome="step_failed", failed_step=dict(self.FAILED))
        self.check(self.local(), row)
        self.check([dict(kind="provider_attempt"), dict(kind="official_tool_result", operation=1)],
                   dict(outcome="no_publication"))
        refusals = (
            (self.local(), dict(outcome="no_publication")),
            ([dict(kind="provider_attempt"), dict(kind="official_tool_result", operation=1)], row),
            (self.local(), dict(row, failed_step=dict(self.FAILED, error="generator_output_empty"))),
            (self.local(), dict(row, failed_step=dict(self.FAILED, operation=3))),
            (self.local(dict(kind="provider_attempt")), row),
            (self.local(dict(kind="official_tool_result", operation=2)), row),
            (self.local(dict(kind="official_tool_failed", **self.FAILED)), row),
            ([dict(kind="official_tool_result", operation=1), dict(kind="official_tool_failed", **self.FAILED)], row),
        )
        for local, bad in refusals:
            with self.assertRaisesRegex(ValueError, "failed_step_evidence"):
                self.check(local, bad)


@NEEDS_AGENTDOJO
class QuickTests(unittest.TestCase):
    def test_quick_ends_where_the_host_does(self):
        from savana_lab import U9
        from savana_lab.quick import quick
        from tests.test_multi_extraction import refund
        from tests.test_savana_lab_quick import Drafter, Extractor
        result = quick(replace(U9, author="deepseek", mapper=None), "banking", "user_task_4",
                       clients=dict(drafter=Drafter(json.dumps(refund())),
                                    generator=Extractor('{"amount": "10", "subject": "Refund"}')))
        self.assertEqual(result.outcome, "step_failed")
        self.assertEqual(result.episode.score["refusal"], "step 2 (dojo.model.extract) indeterminate: extract_fields")
        failed, = result.episode.of("official_tool_failed")
        self.assertEqual({k: failed[k] for k in ("operation", "tool", "status", "error")},
                         dict(operation=2, tool="dojo.model.extract", status="indeterminate", error="extract_fields"))


class ExtractorReplyTests(unittest.TestCase):
    def test_an_empty_reply_is_logged_and_fails_as_empty(self):
        from savana_bench.quarantined_generator import DeepSeekGenerator
        from tests.test_chat_models import Connection, reply
        for content, outcome in (("  ​ ", ValueError("generator_output_empty")), ("Refund", "Refund")):
            record = []
            generator = DeepSeekGenerator("sk-synthetic", connect=lambda timeout: Connection(reply(content), record))
            if isinstance(outcome, BaseException):
                with self.assertRaisesRegex(ValueError, str(outcome)):
                    generator(instruction="Refund", source="x", target="the subject")
            else:
                self.assertEqual(generator(instruction="Refund", source="x", target="the subject"), outcome)
            self.assertEqual(len(generator.log), 1)
            self.assertEqual(generator.log[0]["response_sha256"], hashlib.sha256(content.encode()).hexdigest())

    def test_a_model_that_does_not_answer_is_still_unknown(self):
        from savana_bench.quarantined_generator import DeepSeekGenerator
        from tests.test_chat_models import Connection
        generator = DeepSeekGenerator("sk-synthetic", connect=lambda timeout: Connection(b"{}", [], status=503))
        with self.assertRaisesRegex(RuntimeError, "generator_failed_or_unknown"):
            generator(instruction="Refund", source="x", target="the subject")
        self.assertEqual(generator.log, [])


if __name__ == "__main__":
    unittest.main()
