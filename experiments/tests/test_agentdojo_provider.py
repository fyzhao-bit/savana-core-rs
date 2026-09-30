import concurrent.futures
import copy
import importlib.util
import json
import unittest

from savana_bench.agentdojo_provider import AgentDojoProvider, canonical, decode, synthetic_mail_provider


def call(request_id="test-1", name="mail.allowed", **args):
    return canonical({"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
        "params": {"name": name, "arguments": args or {"to": "Alice", "file": "A", "body": "original"}}})


def status(reply):
    return decode(reply)["result"]["structuredContent"]["savana_status"]


@unittest.skipUnless(importlib.util.find_spec("agentdojo"), "install the explicit AgentDojo test extra")
class ProviderTests(unittest.TestCase):
    def test_real_agentdojo_effect_and_exact_replay(self):
        provider = synthetic_mail_provider()
        frame = call()
        result = provider.exchange(frame)
        self.assertEqual(status(result), "succeeded")
        self.assertEqual(provider.exchange(frame), result)
        self.assertEqual(len(provider.env.inbox.sent), 1)
        self.assertEqual(provider.env.inbox.sent[0].body, "original")
        self.assertEqual(list(provider.env.inbox.sent[0].recipients), ["alice@example.org"])
        self.assertEqual(len(provider.audit), 1)

    def test_official_send_email_function_without_synthetic_alias(self):
        from agentdojo.default_suites.v1.tools.email_client import send_email
        from agentdojo.functions_runtime import FunctionsRuntime, make_function
        env = synthetic_mail_provider().env
        provider = AgentDojoProvider(FunctionsRuntime([make_function(send_email)]), env)
        result = provider.exchange(call(name="send_email", recipients=["test@example.org"], subject="test", body="payload"))
        self.assertEqual(status(result), "succeeded")
        self.assertEqual(env.inbox.sent[0].subject, "test")

    def test_request_id_rebinding_is_not_a_new_effect(self):
        provider = synthetic_mail_provider()
        provider.exchange(call())
        with self.assertRaisesRegex(ValueError, "request_identity_rebound"):
            provider.exchange(call(to="Bob", file="B", body="different"))
        self.assertEqual(len(provider.env.inbox.sent), 1)

    def test_parallel_retry_runs_once(self):
        provider = synthetic_mail_provider()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            replies = list(pool.map(provider.exchange, [call()] * 8))
        self.assertEqual(len(set(replies)), 1)
        self.assertEqual(len(provider.env.inbox.sent), 1)

    def test_unknown_tool_missing_extra_and_wrong_typed_args_never_execute(self):
        for frame in [call(name="delete_all"), call(to="Alice"),
                      call(to="Alice", file="A", body=3),
                      call(to="Alice", file="A", body="x", extra="hidden"),
                      call(to="Alice", file="A", body={"function": "send_email", "args": {}})]:
            provider = synthetic_mail_provider()
            self.assertEqual(status(provider.exchange(frame)), "failed")
            self.assertEqual(provider.env.inbox.sent, [])
            self.assertFalse(provider.audit[0]["invoked"])

    def test_parse_failures_do_not_touch_environment(self):
        provider = synthetic_mail_provider()
        for frame in [b"", b"[]", call() + b" ", b'{"x":1,"x":2}', b'{"x":NaN}', b"[" * 200,
                      call().replace(b'"tools/call"', b'"tools/list"'), b"x" * (32 * 1024 + 1)]:
            with self.assertRaises((ValueError, RecursionError)):
                provider.exchange(frame)
        self.assertEqual(provider.env.inbox.sent, [])

    def test_mutation_then_error_is_unknown_and_cannot_retry(self):
        provider = synthetic_mail_provider()
        original = provider.runtime.run_function
        def failed_after_effect(*args, **kwargs):
            original(*args, **kwargs)
            return "", "synthetic post-effect failure"
        provider.runtime.run_function = failed_after_effect
        reply = provider.exchange(call())
        self.assertEqual(status(reply), "indeterminate")
        self.assertEqual(reply, provider.exchange(call()))
        self.assertEqual(len(provider.env.inbox.sent), 1)

    def test_oversized_or_unserializable_result_is_unknown_after_effect(self):
        for transform in [lambda text, n: "x" * 33000, lambda text, n: object()]:
            provider = synthetic_mail_provider()
            provider.response_transform = transform
            self.assertEqual(status(provider.exchange(call())), "indeterminate")
            self.assertEqual(len(provider.env.inbox.sent), 1)
            self.assertEqual(status(provider.exchange(call())), "indeterminate")
            self.assertEqual(len(provider.env.inbox.sent), 1)

    def test_injection_is_only_in_returned_text_not_control_or_receipt_status(self):
        provider = synthetic_mail_provider(injection=True)
        reply = decode(provider.exchange(call()))
        self.assertEqual(reply["result"]["structuredContent"], {"savana_status": "succeeded"})
        self.assertIn("attacker@example.org", reply["result"]["content"][0]["text"])
        self.assertEqual(list(provider.env.inbox.sent[0].recipients), ["alice@example.org"])

    def test_capacity_exhaustion_does_not_execute(self):
        provider = synthetic_mail_provider()
        provider.max_calls = 1
        provider.exchange(call())
        with self.assertRaisesRegex(ValueError, "provider_call_limit"):
            provider.exchange(call("second"))
        self.assertEqual(len(provider.env.inbox.sent), 1)

    def test_independent_oracle_requires_actual_environment_and_result_byte_flow(self):
        from savana_bench.agentdojo_native import inspect_effects
        provider = synthetic_mail_provider(injection=True)
        first = provider.exchange(call())
        provider.exchange(call("second", to="Bob", file="B", body=first.decode()))
        self.assertTrue(inspect_effects(provider, 2, True))
        provider.env.inbox.sent[1].body = "fabricated"
        self.assertFalse(inspect_effects(provider, 2, True))


if __name__ == "__main__":
    unittest.main()
