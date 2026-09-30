"""Operator wrapper tests; no local socket or deployment is created."""
import asyncio
import importlib.util
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

import savana_core


spec = importlib.util.spec_from_file_location(
    "savana_managed_admin_wrapper_test",
    Path(__file__).parents[1] / "python/savana/managed_admin.py",
)
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)


class ManagedAdminTests(unittest.TestCase):
    def test_native_execution_review_is_unsigned_scoped_and_not_arbitrary_input(self):
        command = dict(schema=1, installation=[1]*32, store=[2]*32, request=[3]*32,
            not_before=100, expires_at=900,
            operation=dict(kind='prepare_planning_execution',task=[4]*32,root=[5]*32))
        with patch.object(savana_core, '_managed_admin_submit_signed') as submit:
            artifact=wrapper.prepare_artifact('command',json.dumps(command).encode())
            self.assertEqual(json.loads(artifact.canonical_bytes()),command)
            submit.assert_not_called()
        for field in ('inputs','run','approval','skip_consent'):
            changed=json.loads(json.dumps(command));changed['operation'][field]=[]
            with self.assertRaises(ValueError):wrapper.prepare_artifact('command',json.dumps(changed).encode())

    @staticmethod
    def planning_draft():
        # Synthetic descriptor/root IDs: preparation is NOT live compilation.
        return {"schema": 1, "root": [4] * 32, "observer_scope": [5] * 32,
                "not_before": 100, "expires_at": 900,
                "operations": [{"id": 1, "clause": 1, "descriptor": [6] * 32,
                                "tool": "mail.send", "after": [],
                                "bindings": [{"argument": name, "slot": [i] * 16}
                                             for i, name in enumerate(("body", "file", "to"), 1)]}],
                "templates": [{"id": 1, "order": [1]}],
                "rounds": [{"id": 1, "opens_at": 110, "advice_cut": 110,
                            "closes_at": 900, "advisor": None, "planner": [7] * 32,
                            "model_profile": 1, "mode": "registered_template_v04",
                            "public_view": list(b"approved context"), "template_ids": [1],
                            "question_codes": [], "max_deliveries": 1}],
                "delivery_schedule": [{"id": 1, "round": 1, "role": "planner",
                                       "opens_at": 110, "closes_at": 900}],
                "release_model_views": True, "max_replacements": 0}

    def test_planning_draft_and_command_use_distinct_native_signing_domains(self):
        draft = self.planning_draft()
        command = {"schema": 1, "installation": [1] * 32, "store": [2] * 32,
                   "request": [3] * 32, "not_before": 100, "expires_at": 900,
                   "operation": {"kind": "compile_planning", "task": [8] * 32, "draft": draft}}
        with patch.object(savana_core, "_managed_admin_submit_signed") as submit:
            d = wrapper.prepare_artifact("planning_draft", json.dumps(draft).encode())
            c = wrapper.prepare_artifact("command", json.dumps(command).encode())
            self.assertEqual(json.loads(d.canonical_bytes()), draft)
            self.assertEqual(json.loads(c.canonical_bytes()), command)
            self.assertNotEqual(d.signing_digest(), c.signing_digest())
            for kind, prepared in [("planning_draft", d), ("command", c)]:
                again = wrapper.prepare_artifact(kind, prepared.canonical_bytes())
                self.assertEqual(again.signing_digest(), prepared.signing_digest())
            submit.assert_not_called()

    def test_observation_selector_is_signed_and_unknown_fields_are_rejected(self):
        draft = self.planning_draft()
        original = wrapper.prepare_artifact("planning_draft", json.dumps(draft).encode())
        draft["rounds"][0]["observations"] = [{"source": 1, "path": ["result", "status"]}]
        observed = wrapper.prepare_artifact("planning_draft", json.dumps(draft).encode())
        self.assertNotEqual(original.signing_digest(), observed.signing_digest())
        draft["rounds"][0]["observations"][0]["send_raw"] = True
        with self.assertRaises(ValueError):
            wrapper.prepare_artifact("planning_draft", json.dumps(draft).encode())
        raw = original.canonical_bytes()
        duplicate = raw.replace(b'{', b'{"schema":1,', 1)
        with self.assertRaises(ValueError):
            wrapper.prepare_artifact("planning_draft", duplicate)

    def test_recipe_approval_preparation_uses_separate_rust_format(self):
        document = {"schema": 1, "recipe_schema": 1, "installation": [1] * 32,
                    "manifest": [2] * 32, "task": [3] * 32, "root": [4] * 32,
                    "profile": [5] * 32, "deployment_generation": 7,
                    "not_before": 1, "expires_at": 10,
                    "bindings": [{"operation": 1, "recipe": [6] * 32}]}
        with patch.object(savana_core, "_managed_admin_submit_signed") as submit:
            prepared = wrapper.prepare_artifact("recipe_approval", json.dumps(document).encode())
            self.assertEqual(json.loads(prepared.canonical_bytes()), document)
            self.assertEqual(len(prepared.signing_digest()), 32)
            submit.assert_not_called()
        document["recipe_schema"] = 2
        with self.assertRaises(ValueError):
            wrapper.prepare_artifact("recipe_approval", json.dumps(document).encode())

    def test_prepare_runs_real_rust_canonicalization_without_submission(self):
        document = {"operation": {"kind": "create_resource", "source": [4] * 32,
                                  "namespace": [5] * 32, "label": "private", "content": [6]},
                    "expires_at": 10, "not_before": 1, "request": [3] * 32,
                    "store": [2] * 32, "installation": [1] * 32, "schema": 1}
        with patch.object(savana_core, "_managed_admin_submit_signed") as submit:
            prepared = wrapper.prepare_artifact("command", json.dumps(document).encode())
            self.assertEqual(json.loads(prepared.canonical_bytes()), document)
            self.assertEqual(len(prepared.signing_digest()), 32)
            self.assertEqual(repr(prepared), "PreparedPrivateArtifact(<private unsigned artifact>)")
            again = wrapper.prepare_artifact("command", prepared.canonical_bytes())
            self.assertEqual(again.signing_digest(), prepared.signing_digest())
            submit.assert_not_called()
        with self.assertRaises(TypeError):
            savana_core._PreparedPrivateArtifact()

    def test_prepare_rejects_unknown_kind_or_ambiguous_fields(self):
        for kind, data in [("execute", b"{}"), ("command", b'{"schema":1,"schema":2}'),
                           ("planning_profile", b"{}"), ("source_policy", b"")]:
            with self.assertRaises(ValueError):
                wrapper.prepare_artifact(kind, data)
        with self.assertRaises(TypeError):
            wrapper.prepare_artifact("command", {})

    def test_wrapper_rejects_invalid_type_or_size_before_native_call(self):
        for command, signature in [("private", b"x" * 64), (b"", b"x" * 64),
                                   (b"x" * (256 * 1024 + 1), b"x" * 64),
                                   (b"{}", b"short")]:
            with patch.object(savana_core, "_managed_admin_submit_signed") as native:
                with self.assertRaises((TypeError, ValueError)):
                    asyncio.run(wrapper.submit_signed(command, signature))
                native.assert_not_called()

    def test_wrapper_passes_exact_bytes_in_worker_without_retry(self):
        main_thread = threading.get_ident()
        receipt = object()
        command, signature = b"canonical private bytes", b"s" * 64

        def native(c, s):
            self.assertNotEqual(threading.get_ident(), main_thread)
            self.assertIs(c, command)
            self.assertIs(s, signature)
            return receipt

        with patch.object(savana_core, "_managed_admin_submit_signed", side_effect=native) as call:
            self.assertIs(asyncio.run(wrapper.submit_signed(command, signature)), receipt)
            self.assertEqual(call.call_count, 1)
        with patch.object(savana_core, "_managed_admin_submit_signed", side_effect=RuntimeError("not confirmed")) as call:
            with self.assertRaises(RuntimeError):
                asyncio.run(wrapper.submit_signed(command, signature))
            self.assertEqual(call.call_count, 1)

    def test_real_native_rejects_invalid_signature_and_cannot_forge_receipt(self):
        with self.assertRaises(ValueError):
            savana_core._managed_admin_submit_signed(b"{}", b"short")
        with self.assertRaises(RuntimeError):
            savana_core._managed_admin_submit_signed(b"{}", b"s" * 64)
        with self.assertRaises(TypeError):
            savana_core._ManagedAdminReceipt()


if __name__ == "__main__":
    unittest.main()
