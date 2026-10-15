"""chat_models: every role's model by name, one request builder and one client.

DeepSeek's request bytes are what every earlier run sent (the offline
verifier recomputes logged digests from them); another provider's are the
same OpenAI-compatible request without DeepSeek's field; a reply must come
from the endpoint's model; the key only ever travels in the request header."""
import importlib.util
import json
import unittest
from unittest import mock

from savana_bench.chat_models import (DEFAULT_MODEL, ENDPOINTS, MODEL_NAMES, ChatClient, ChatProposer, chat_body,
                                      endpoint, key_material, parse_keys)
from savana_bench.drafted_tasks import EXTRACTOR_MODELS
from savana_bench.planner_experiment import EXECUTOR_MODELS, PLANNER_MODELS, experiment_cases, run_executor_model

KEY = "sk-synthetic-chat-credential"
MESSAGES = [dict(role="system", content="Return only a JSON object."), dict(role="user", content="héllo")]


def reply(content, model="deepseek-flash", finish="stop", **message):
    return json.dumps(dict(model=model, choices=[dict(finish_reason=finish, message=dict(
        role="assistant", content=content, **message))], usage=dict(prompt_tokens=7, completion_tokens=3))).encode()


class Connection:
    def __init__(self, body, record, status=200):
        self.body, self.record, self.status, self.sock, self.closed = body, record, status, None, False

    def request(self, method, path, body=None, headers=None):
        self.record.append(dict(method=method, path=path, body=body, headers=headers))

    def getresponse(self):
        connection = self

        class Response:
            status = connection.status

            def read(self, size):
                return connection.body[:size]
        return Response()

    def close(self):
        self.closed = True


def client(name, body, status=200):
    record = []
    return ChatClient(name, KEY, connect=lambda timeout: Connection(body, record, status)), record


class RegistryTests(unittest.TestCase):
    def test_every_role_takes_every_registered_model_and_defaults_to_the_first(self):
        self.assertEqual(DEFAULT_MODEL, "deepseek-flash")
        for names in (PLANNER_MODELS, EXECUTOR_MODELS):
            self.assertEqual(names, MODEL_NAMES)
        self.assertEqual(set(EXTRACTOR_MODELS), set(MODEL_NAMES))
        self.assertEqual((PLANNER_MODELS[0], EXTRACTOR_MODELS[0], EXECUTOR_MODELS[0]), (DEFAULT_MODEL,) * 3)
        with self.assertRaisesRegex(ValueError, "unknown_model"):
            endpoint("gpt-9")

    def test_gpt_4o_mini_is_openais_and_replies_as_a_dated_snapshot(self):
        e = endpoint("gpt-4o-mini")
        self.assertEqual((e.provider, e.host, e.path, e.model),
                         ("openai", "api.openai.com", "/v1/chat/completions", "gpt-4o-mini"))
        self.assertNotIn("thinking", json.loads(chat_body("gpt-4o-mini", MESSAGES, max_tokens=512, json_object=True)))
        self.assertTrue(e.named_in_reply("gpt-4o-mini-2024-07-18"))
        self.assertFalse(e.named_in_reply("gpt-4o-2024-08-06"))
        self.assertFalse(endpoint("deepseek-flash").named_in_reply("deepseek-flash-2"))

    def test_deepseek_bodies_are_the_bytes_every_earlier_run_sent(self):
        for name in ("deepseek-flash", "deepseek-v4-pro"):
            for max_tokens, json_object in ((2048, True), (256, False)):
                old = dict(model=name, messages=MESSAGES, temperature=0, max_tokens=max_tokens,
                           thinking={"type": "disabled"}, stream=False)
                if json_object:
                    old["response_format"] = {"type": "json_object"}
                self.assertEqual(chat_body(name, MESSAGES, max_tokens=max_tokens, json_object=json_object),
                                 json.dumps(old, ensure_ascii=False, allow_nan=False).encode())

    def test_another_provider_gets_the_same_request_without_deepseeks_field(self):
        sent = json.loads(chat_body("gpt-4.1-mini", MESSAGES, max_tokens=512, json_object=True))
        self.assertEqual(sent, dict(model="gpt-4.1-mini", messages=MESSAGES, temperature=0, max_tokens=512,
                                    stream=False, response_format={"type": "json_object"}))
        self.assertEqual((ENDPOINTS["gpt-4.1-mini"].host, ENDPOINTS["gpt-4.1-mini"].path),
                         ("api.openai.com", "/v1/chat/completions"))

    def test_the_spec_takes_any_registered_model_and_one_executor_per_run(self):
        case, = experiment_cases("drafted+planner=gpt-4.1-mini+extractor=qwen-plus+executor=qwen-plus"
                                 ":banking:user_task_0")
        self.assertEqual((case["planner_model"], case["extractor_model"], case["executor_model"]),
                         ("gpt-4.1-mini", "qwen-plus", "qwen-plus"))
        self.assertNotIn("executor_model", experiment_cases("drafted:banking:user_task_0")[0])
        self.assertEqual(run_executor_model([case]), "qwen-plus")
        self.assertEqual(run_executor_model(experiment_cases("drafted:banking:user_task_0")), DEFAULT_MODEL)
        for spec in ("drafted+planner=gpt-9:banking:user_task_0", "drafted+executor=other:banking:user_task_0"):
            with self.assertRaises(ValueError):
                experiment_cases(spec)


class KeyTests(unittest.TestCase):
    def test_a_bare_key_is_deepseeks_and_a_set_is_compact_json(self):
        self.assertEqual(parse_keys(b"sk-abc\n"), {"deepseek": "sk-abc"})
        self.assertEqual(key_material({"deepseek": "sk-abc"}), "sk-abc")
        material = key_material({"openai": "sk-o", "deepseek": "sk-d"})
        self.assertEqual(material, '{"deepseek":"sk-d","openai":"sk-o"}')
        self.assertEqual(parse_keys(material), {"deepseek": "sk-d", "openai": "sk-o"})
        for bad in (b"", b"sk with space", b"{}", b'{"Bad":"k"}', b'{"openai":""}', b"[1]", b"x" * 2049,
                    b'{"openai":"k k"}', "sk-é".encode()):
            with self.subTest(bad=bad[:20]), self.assertRaises(ValueError):
                parse_keys(bad)


class ClientTests(unittest.TestCase):
    def test_one_post_the_key_only_in_the_header(self):
        chat, record = client("deepseek-flash", reply('{"ok":1}'))
        body = chat_body("deepseek-flash", MESSAGES, max_tokens=64, json_object=True)
        content, usage, finish = chat.complete(body, timeout=5)
        self.assertEqual((content, usage, finish), ('{"ok":1}', dict(prompt_tokens=7, completion_tokens=3), "stop"))
        sent, = record
        self.assertEqual((sent["method"], sent["path"], sent["body"]), ("POST", "/chat/completions", body))
        self.assertEqual(sent["headers"]["Authorization"], "Bearer " + KEY)
        self.assertNotIn(KEY, repr(chat))

    def test_a_reply_must_come_from_the_endpoints_model(self):
        dated, _ = client("gpt-4.1-mini", reply("x", model="gpt-4.1-mini-2025-04-14"))
        self.assertEqual(dated.complete(b"{}", timeout=5)[0], "x")
        for name, model in (("gpt-4.1-mini", "gpt-4.1"), ("deepseek-flash", "deepseek-flash-2"),
                            ("deepseek-flash", "deepseek-v4-pro")):
            chat, _ = client(name, reply("x", model=model))
            with self.subTest(name=name, model=model), self.assertRaisesRegex(ValueError, "provider_model"):
                chat.complete(b"{}", timeout=5)

    def test_anything_but_one_bounded_finished_message_fails(self):
        cases = ((reply("x"), 500, "provider_status"),
                 (reply("x", finish="length"), 200, "provider_incomplete"),
                 (reply("x", tool_calls=[{}]), 200, "provider_tool_call"),
                 (reply("x" * 17000), 200, "provider_size"),
                 (b"x" * 70000, 200, "provider_size"))
        for body, status, error in cases:
            chat, _ = client("deepseek-flash", body, status)
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                chat.complete(b"{}", timeout=5)
        chat, _ = client("deepseek-flash", reply("x", finish="length"))
        self.assertEqual(chat.complete(b"{}", timeout=5, finish=("stop", "length"))[2], "length")
        chat.close()
        with self.assertRaisesRegex(RuntimeError, "model_closed"):
            chat.complete(b"{}", timeout=5)


class Job:
    def __init__(self, role="planner"):
        self.view = dict(model_profile=1, role=role, mode="registered_template_v04", public_view=b"[1,2]")
        self.proposals = []

    def encode_proposal(self, proposed):
        self.proposals.append(proposed)


@unittest.skipUnless(importlib.util.find_spec("savana") and importlib.util.find_spec("savana_core"),
                     "the SDK packages (crates/savana-core-py/python) are not importable")
class ExecutorParityTests(unittest.TestCase):
    def test_the_executor_sends_the_sdk_models_exact_request(self):
        import time
        from savana.fused_deepseek import DeepSeekModel
        answer = reply('{"choice":{"kind":"registered_template","template":1}}')
        for role in ("planner", "advisor"):
            record = []

            class Sdk(Connection):
                def __init__(self, host, timeout=None, context=None):
                    super().__init__(answer, record)

                def getresponse(self):
                    response = super().getresponse()
                    data = [self.body]
                    response.read1 = lambda size: data.pop() if data else b""
                    return response
            with mock.patch("savana.fused_deepseek.http.client.HTTPSConnection", Sdk):
                sdk = DeepSeekModel(KEY, profiles={1: "deepseek-flash"})
                self.assertEqual(sdk(Job(role), time.monotonic() + 5), {"choice": {"kind": "registered_template",
                                                                                   "template": 1}})
            ours = []
            proposer = ChatProposer(KEY, profiles={1: "deepseek-flash"},
                                    connect=lambda timeout: Connection(answer, ours))
            job = Job(role)
            self.assertEqual(proposer(job, time.monotonic() + 5), sdk_proposal := job.proposals[0])
            self.assertEqual(sdk_proposal, {"choice": {"kind": "registered_template", "template": 1}})
            self.assertEqual(ours[0]["body"], record[0]["body"])
            self.assertEqual((proposer.calls, proposer.input_bytes), (1, len(record[0]["body"])))


if __name__ == "__main__":
    unittest.main()
