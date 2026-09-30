import base64
import hashlib
import importlib.util
import unittest

from savana_bench.agentdojo_provider import canonical, synthetic_mail_provider
from savana_bench.agentdojo_publication import SyntheticResultReceiver
from savana_bench.agentdojo_native import inspect_effects


def call(identifier, recipient, label, body):
    return canonical({"jsonrpc": "2.0", "id": identifier, "method": "tools/call",
                      "params": {"name": "mail.allowed", "arguments": {
                          "to": recipient, "file": label, "body": body}}})


def release(raw, **changes):
    body = {"resource": "result:" + "03" * 32, "destination": "application-turn:" + "04" * 32,
            "payload": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()}
    body.update(changes)
    return canonical({"request_id": "release-1", "method": "POST",
                      "path": "/savana/final-result-release", "body": body})


@unittest.skipUnless(importlib.util.find_spec("agentdojo"), "explicit AgentDojo test extra required")
class PublicationTests(unittest.TestCase):
    def prepared(self):
        p = SyntheticResultReceiver(synthetic_mail_provider(injection=True), turn="04" * 32)
        first = p.exchange(call("a", "Alice", "A", "original"))
        last = p.exchange(call("b", "Bob", "B", first.decode()))
        return p, first, last

    def test_terminal_bytes_publish_once_and_keep_injection_as_data(self):
        p, _, last = self.prepared()
        response = p.exchange(release(last))
        self.assertEqual(response, p.exchange(release(last)))
        self.assertEqual(len(p.publications), 1)
        self.assertEqual(len(p.env.inbox.sent), 2)
        self.assertEqual(p.publications[0]["payload_sha256"], hashlib.sha256(last).hexdigest())
        self.assertTrue(inspect_effects(p, 2, True, True))
        self.assertFalse(inspect_effects(p, 2, True, False))
        p.publications[0]["payload_sha256"] = "0" * 64
        self.assertFalse(inspect_effects(p, 2, True, True))

    def test_wrong_result_turn_namespace_padding_and_extra_fields_are_rejected(self):
        p, first, last = self.prepared()
        for frame in [release(first), release(b"original"), release(b"invented"),
                      release(last, destination="application-turn:" + "05" * 32),
                      release(last, resource="input:" + "03" * 32),
                      release(last, resource="result:" + "00" * 32),
                      release(last, payload=base64.urlsafe_b64encode(last).decode() + "="),
                      release(last, extra=True)]:
            with self.assertRaises(ValueError):
                p.exchange(frame)
        self.assertEqual(p.publications, [])
        self.assertEqual(len(p.env.inbox.sent), 2)

    def test_early_publish_rebinding_and_post_publication_execution_rejected(self):
        p = SyntheticResultReceiver(synthetic_mail_provider(), turn="04" * 32)
        with self.assertRaises(ValueError):
            p.exchange(release(b"fabricated"))
        p, _, last = self.prepared()
        p.exchange(release(last))
        with self.assertRaisesRegex(ValueError, "release_rebound"):
            p.exchange(release(last, resource="result:" + "06" * 32))
        with self.assertRaisesRegex(ValueError, "already_published"):
            p.exchange(call("c", "Carol", "C", "unexpected"))
        self.assertEqual(len(p.publications), 1)


if __name__ == "__main__":
    unittest.main()
