"""The full reviewed AgentDojo catalog: coverage, profile shape, decoding, and
real AgentDojo 0.1.35 environments behind the per-suite provider."""
import hashlib
import unittest

from savana_bench.agentdojo_provider import canonical, decode
from savana_bench.dojo_catalog import (CATALOG, KINDS, OMIT, SENTINELS, SUITE_TOOLS, SUITES, catalog_document,
                                       decode_argument, entry, official_call, suite_operations)

ORIGINAL = ("dojo.calendar.search", "dojo.calendar.day", "dojo.email.search", "dojo.email.unread",
            "dojo.file.list", "dojo.file.search_name", "dojo.file.search", "dojo.file.append")
SAMPLE = {"text": "x", "opt_text": "", "null_text": "", "list": ["a", "b"], "opt_list": [], "number": "12.5",
          "opt_number": "", "integer": "3", "opt_integer": "", "boolean": "false",
          "opt_boolean": "", "permission": "r", "attachments": [], "guard": "always"}


def call(name, arguments, request_id):
    return canonical({"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                      "params": {"name": name, "arguments": arguments}})


def arguments_for(operation, **values):
    out = {}
    for name, _role, _upstream, kind in entry(operation)["fields"]:
        out[name] = SENTINELS[name] if kind == "fixed" else values.get(name, SAMPLE[kind])
    return out


class CatalogShapeTests(unittest.TestCase):
    def test_every_agentdojo_tool_in_every_suite_is_reviewed(self):
        from agentdojo.task_suite.load_suites import get_suite
        covered = {t["upstream"] for t in CATALOG}
        for name in SUITES:
            tools = {t.name for t in get_suite("v1.2.2", name).tools}
            self.assertEqual(tools, SUITE_TOOLS[name], name)
            self.assertEqual(tools - covered, set(), name)
            served = suite_operations(tools)
            self.assertEqual({entry(o)["upstream"] for o in served}, tools, name)

    def test_profiles_have_one_resource_destination_and_payload(self):
        operations = [t["operation"] for t in CATALOG]
        self.assertEqual(len(operations), len(set(operations)))
        for tool in CATALOG:
            names = [f[0] for f in tool["fields"]]
            roles = [f[1] for f in tool["fields"]]
            self.assertEqual(len(names), len(set(names)), tool["operation"])
            self.assertTrue(3 <= len(names) <= 32)
            for role in ("resource", "destination", "payload"):
                self.assertEqual(roles.count(role), 1, (tool["operation"], role))
            for name, role, upstream, kind in tool["fields"]:
                self.assertIn(role, ("resource", "destination", "payload", "parameter"))
                self.assertTrue(kind == "fixed" or kind in KINDS)
                # Fixed controls and the condition gate are never forwarded.
                self.assertEqual(kind in ("fixed", "guard"), upstream is None)
                if kind == "fixed":
                    self.assertIn(name, SENTINELS)
            # Reads stay on the fixed synthetic controls; writes declare their
            # real target and destination where the function has one.
            if tool["effect"] == "read":
                self.assertTrue(all(r == "parameter" for (n, r, u, k) in tool["fields"] if k != "fixed"))

    def test_original_workspace_entries_are_unchanged(self):
        from savana_bench.agentdojo_tasks import catalog_json
        old = catalog_json()
        new = catalog_document("workspace")
        by_name = {t["operation"]: t for t in (*new["read_tools"], *new["write_tools"])}
        for tool in (*old["read_tools"], *old["write_tools"]):
            if tool["operation"] in ORIGINAL:
                self.assertEqual(by_name[tool["operation"]], tool)
        self.assertEqual([t["operation"] for t in new["read_tools"][:7]], list(ORIGINAL[:7]))

    def test_each_suite_catalog_fits_one_task_context(self):
        # The owner's task-authorization context lists at most 64 tools, so a
        # deployment ships exactly one suite (plus the two model tools and the
        # deterministic compute tool).
        from savana_bench.agentdojo_tasks import catalog_json
        for name in SUITES:
            doc = catalog_json(name)
            operations = [t["operation"] for t in (*doc["read_tools"], *doc["write_tools"])]
            self.assertLessEqual(len(operations) + 1, 64, name)
            self.assertEqual({entry(o)["upstream"] for o in operations if o.startswith("dojo.") and
                              not o.startswith(("dojo.model.", "dojo.compute."))}, set(SUITE_TOOLS[name]), name)
            self.assertIn("dojo.compute.table", operations, name)

    def test_every_adapter_decodes_to_valid_official_arguments(self):
        from agentdojo.task_suite.load_suites import get_suite
        functions = {}
        for name in SUITES:
            functions.update({t.name: t for t in get_suite("v1.2.2", name).tools})
        for tool in CATALOG:
            upstream, official = official_call(tool["operation"], arguments_for(tool["operation"]))
            self.assertEqual(upstream, tool["upstream"])
            functions[upstream].parameters.model_validate(official)


class DecodingTests(unittest.TestCase):
    def test_rules_are_exact_and_refuse_anything_else(self):
        self.assertEqual(decode_argument("list", ["a@x.com", "b@y.com"]), ["a@x.com", "b@y.com"])
        self.assertIs(decode_argument("opt_list", []), OMIT)
        self.assertEqual(decode_argument("number", "100"), 100.0)
        self.assertEqual(decode_argument("number", "0.5"), 0.5)
        self.assertEqual(decode_argument("integer", "7"), 7)
        self.assertIs(decode_argument("boolean", "true"), True)
        self.assertEqual(decode_argument("attachments", ["13", "2"]),
                         [{"type": "file", "file_id": "13"}, {"type": "file", "file_id": "2"}])
        self.assertEqual(decode_argument("text", ""), "")
        self.assertIsNone(decode_argument("null_text", ""))
        self.assertEqual(decode_argument("null_text", "2024-05-01 10:00"), "2024-05-01 10:00")
        # A list kind takes typed items only: never one joined text.
        for kind, text in (("list", []), ("list", "a; b"), ("list", ["a", ""]), ("list", [" a"]),
                           ("list", ["a", 1]), ("opt_list", ""), ("text", ["a"]), ("number", "1e3"),
                           ("number", "-5"), ("number", "01"), ("number", "nan"), ("integer", "1.0"),
                           ("integer", "+1"), ("boolean", "True"), ("boolean", ""), ("permission", "w"),
                           ("text", None)):
            with self.assertRaises(ValueError, msg=(kind, text)):
                decode_argument(kind, text)

    def test_official_call_checks_sentinels_and_field_set(self):
        arguments = arguments_for("dojo.bank.send_money", recipient="GB29NWBK60161331926819",
                                  amount="100", subject="rent", date="2022-04-01")
        self.assertEqual(official_call("dojo.bank.send_money", arguments),
                         ("send_money", {"recipient": "GB29NWBK60161331926819", "amount": 100.0,
                                         "subject": "rent", "date": "2022-04-01"}))
        for bad in (dict(arguments, to="attacker"), dict(arguments, body="x"),
                    {k: v for k, v in arguments.items() if k != "subject"}, dict(arguments, extra="")):
            with self.assertRaises(ValueError):
                official_call("dojo.bank.send_money", bad)
        with self.assertRaises(ValueError):
            official_call("dojo.bank.wire_everything", arguments)


class ProviderTests(unittest.TestCase):
    def provider(self, name, task="user_task_0", max_calls=4):
        from agentdojo.task_suite.load_suites import get_suite
        from savana_bench.dojo_provider import dojo_provider
        suite = get_suite("v1.2.2", name)
        env = suite.get_user_task_by_id(task).init_environment(suite.load_and_inject_default_environment({}))
        return env, dojo_provider(suite, env, max_calls=max_calls)

    def result(self, provider, operation, request_id, **values):
        reply = decode(provider.exchange(call(operation, arguments_for(operation, **values), request_id)))
        return reply["result"]["structuredContent"]["savana_status"], reply["result"]["content"]

    def test_banking_transfer_runs_the_official_function_once(self):
        env, provider = self.provider("banking")
        before = len(env.bank_account.transactions)
        status, _ = self.result(provider, "dojo.bank.send_money", "s1", recipient="DE89370400440532013000",
                                amount="12.5", subject="dinner", date="2022-05-01")
        self.assertEqual(status, "succeeded")
        self.assertEqual(len(env.bank_account.transactions), before + 1)
        sent = env.bank_account.transactions[-1]
        self.assertEqual((sent.recipient, sent.amount, sent.subject), ("DE89370400440532013000", 12.5, "dinner"))

    def test_workspace_email_list_and_travel_list_reads(self):
        env, provider = self.provider("workspace")
        status, _ = self.result(provider, "dojo.email.send", "e1", recipients=["a@x.com", "b@y.com"],
                                subject="hi", text="hello", attachments=[])
        self.assertEqual(status, "succeeded")
        self.assertEqual(env.inbox.sent[-1].recipients, ["a@x.com", "b@y.com"])
        env, provider = self.provider("travel")
        status, content = self.result(provider, "dojo.travel.hotel_prices", "t1",
                                      hotel_names=["Le Marais Boutique", "Good Night"])
        self.assertEqual(status, "succeeded")
        self.assertIn("Le Marais Boutique", content[0]["text"])

    def test_other_suites_tools_and_the_generator_are_not_served(self):
        env, provider = self.provider("slack")
        snapshot = env.model_dump(mode="json")
        for request_id, operation in (("x1", "dojo.bank.send_money"), ("x2", "dojo.email.send"),
                                      ("x3", "dojo.model.generate")):
            reply = decode(provider.exchange(call(operation, {"body": ""}, request_id)))
            self.assertEqual(reply["result"]["structuredContent"]["savana_status"], "failed")
        self.assertEqual([r["invoked"] for r in provider.audit], [False, False, False])
        self.assertEqual(env.model_dump(mode="json"), snapshot)

    def test_a_bad_sentinel_or_encoding_is_refused_before_any_effect(self):
        env, provider = self.provider("slack")
        snapshot = hashlib.sha256(canonical(env.model_dump(mode="json"))).hexdigest()
        args = arguments_for("dojo.slack.send_channel", channel="general", text="hi")
        for request_id, bad in (("b1", dict(args, body="exfiltrate")), ("b2", dict(args, calendar="x"))):
            reply = decode(provider.exchange(call("dojo.slack.send_channel", bad, request_id)))
            self.assertNotEqual(reply["result"]["structuredContent"]["savana_status"], "succeeded")
        self.assertEqual(hashlib.sha256(canonical(env.model_dump(mode="json"))).hexdigest(), snapshot)


if __name__ == "__main__":
    unittest.main()
