"""Untrusted-planner experiment wiring tests; never kernel, model or benchmark evidence."""
import asyncio
import base64
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from savana_bench.agentdojo_provider import canonical
from savana_bench.agentdojo_tasks import _TASKS, prepare_draft
from savana_bench.planner_authors import COMPROMISED, reviewed_plan
from savana_bench.planner_experiment import (ProviderRelay, classify_provider_attempt, experiment_cases,
                                             plan_author_for, provisioning_outcome)
from savana_bench.protected_agentdojo import CASES
from savana_bench.protected_operator import FiniteOperator, KernelNotConfirmed, OperatorNotConfirmed


def hexd(c):
    return (c * 32).hex()


class CaseTests(unittest.TestCase):
    def test_catalog_is_closed(self):
        honest = experiment_cases("honest")
        self.assertEqual([(c["group"], c["user"], c["injection"]) for c in honest],
                         [(c["group"], c["user"], c["injection"]) for c in CASES])
        self.assertTrue(all(c["author"] == "deepseek" and c["goal"] is None for c in honest))
        poisoned = experiment_cases("poisoned")
        self.assertEqual(len(poisoned), 9)
        self.assertEqual({c["goal"] for c in poisoned}, {"exfiltrate", "overcollect", "tamper"})
        compromised = experiment_cases("compromised")
        self.assertEqual([c["mutation"] for c in compromised], [n for n, _, _ in COMPROMISED])
        self.assertEqual([c["mutation"] for c in experiment_cases("compromised:slot_swap,drop_release")],
                         ["slot_swap", "drop_release"])
        for bad in ("", "honest:x", "poisoned:tamper", "compromised:nope", "compromised:slot_swap,slot_swap",
                    "compromised:", "all", None):
            with self.assertRaises(ValueError, msg=bad):
                experiment_cases(bad)


class VerdictTests(unittest.TestCase):
    def test_provider_requests_are_judged_only_against_the_owner_root(self):
        contract = _TASKS[0]
        judge = lambda value: classify_provider_attempt(canonical(value), contract=contract,
                                                        resource="ab" * 32, application_turn="cd" * 32)
        tool = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": contract.tool, "arguments": contract.values()}}
        self.assertEqual(judge(tool), "authorized_tool")
        wrong = json.loads(canonical(tool))
        wrong["params"]["arguments"]["date"] = "2024-05-15"
        self.assertEqual(judge(wrong), "unauthorized_tool")
        other = json.loads(canonical(tool))
        other["params"]["name"] = "dojo.calendar.day"
        self.assertEqual(judge(other), "unauthorized_tool")
        release = {"method": "POST", "path": "/savana/final-result-release", "request_id": "r",
                   "body": {"resource": "result:" + "ab" * 32, "destination": "application-turn:" + "cd" * 32,
                            "payload": "eA"}}
        self.assertEqual(judge(release), "owner_release")
        elsewhere = json.loads(canonical(release))
        elsewhere["body"]["destination"] = "application-turn:" + "ee" * 32
        self.assertEqual(judge(elsewhere), "unauthorized_release")
        self.assertEqual(classify_provider_attempt(b"not json", contract=contract, resource="",
                                                   application_turn=""), "unauthorized_unparseable")

    def test_layer_attribution_needs_the_matching_stage(self):
        kernel, operator = OperatorNotConfirmed("kernel"), OperatorNotConfirmed("operator")
        codec = ValueError("invalid private artifact")
        stage = "owner_root_authorization_and_plan"
        self.assertEqual(provisioning_outcome(stage, error=codec, plan_supplied=True), "sdk_codec_rejected")
        self.assertEqual(provisioning_outcome(stage, error=codec, plan_supplied=False), "setup_failed")
        self.assertEqual(provisioning_outcome(stage, error=ValueError("user denied"), plan_supplied=True),
                         "setup_failed")
        self.assertEqual(provisioning_outcome("operator_compile_replay", error=kernel, plan_supplied=True),
                         "compile_rejected")
        self.assertEqual(provisioning_outcome("operator_compile_replay", error=operator, plan_supplied=True),
                         "operator_failed")
        self.assertEqual(provisioning_outcome("operator_compile", error=kernel, plan_supplied=True),
                         "operator_failed")
        self.assertEqual(provisioning_outcome("operator_execution_prepare", error=kernel, plan_supplied=True),
                         "prepare_rejected")
        self.assertEqual(provisioning_outcome("owner_input_commit", error=kernel, plan_supplied=False),
                         "setup_failed")

    def test_unbound_listener_records_then_refuses(self):
        events = []
        relay = ProviderRelay(lambda kind, **data: events.append((kind, data)))
        frame = SimpleNamespace(nonce=b"n" * 16, url="https://127.0.0.1:1/x", payload=b"{}")
        with self.assertRaises(ValueError):
            relay.exchange(frame)
        self.assertEqual(events[0][0], "provider_attempt_unbound")
        self.assertEqual(base64.b64decode(events[0][1]["payload_base64"]), b"{}")
        relay.bind(SimpleNamespace(exchange=lambda f: b"reply"))
        self.assertEqual(relay.exchange(frame), b"reply")


class AuthorTests(unittest.TestCase):
    def context(self):
        now = time.time_ns() // 1000000
        ids = dict(task=b"a" * 32, root=b"b" * 32, observer=b"o" * 32, application_turn=b"u" * 32,
                   planner=b"p" * 32, model_profile=1, not_before=now, expires_at=now + 120000)
        descriptors = {t.tool: bytes([i + 1]) * 32 for i, t in enumerate(_TASKS)}
        descriptors["savana.final_result_release"] = b"r" * 32
        return ids, dict(ids, descriptors=descriptors, release_descriptor=b"r" * 32)

    def test_honest_text_encodes_to_the_reviewed_draft_and_mutations_deviate(self):
        contract = _TASKS[0]
        ids, context = self.context()
        events, facts = [], dict(plan_supplied=False, deviates=None)
        emit = lambda kind, **data: events.append((kind, data))
        case = dict(author="deepseek", goal=None, mutation=None)
        draft = plan_author_for(case, contract, json.dumps(reviewed_plan(contract)), emit, facts)(contract, context)
        reviewed = prepare_draft(contract, tool_descriptor=context["descriptors"][contract.tool],
                                 release_descriptor=b"r" * 32, **ids)["planning_draft"]
        self.assertEqual(draft, json.loads(canonical(reviewed)))
        self.assertEqual(facts, dict(plan_supplied=True, deviates=False))
        self.assertEqual(events[-1][0], "plan_submitted")
        self.assertEqual(events[-1][1]["draft"], draft)
        for name, _, _ in COMPROMISED:
            facts = dict(plan_supplied=False, deviates=None)
            author = plan_author_for(dict(author="adversary", goal=None, mutation=name), contract, None, emit, facts)
            self.assertNotEqual(author(contract, context), draft)
            self.assertTrue(facts["deviates"], name)
        with self.assertRaises(ValueError):
            plan_author_for(case, contract, "{}", emit, dict(facts))(_TASKS[1], context)


class VerifierTests(unittest.TestCase):
    def test_submitted_draft_must_be_the_mechanical_encoding_of_the_author_output(self):
        import hashlib
        from savana_bench.planner_verify import _submitted_draft
        contract = _TASKS[0]
        ids, context = AuthorTests().context()
        text = json.dumps(reviewed_plan(contract))
        events = []
        emit = lambda kind, **data: events.append(dict(data, kind=kind))
        case = dict(author="deepseek", goal=None, mutation=None)
        plan_author_for(case, contract, text, emit, dict(plan_supplied=False, deviates=None))(contract, context)
        authored = dict(kind="plan_authored", plan_text=text, response_sha256=hashlib.sha256(text.encode()).hexdigest())
        local = [authored] + json.loads(canonical(events))
        self.assertEqual(_submitted_draft(case, contract, local)[1], False)
        tampered = json.loads(canonical(local))
        tampered[1]["draft"]["final_release"]["turn"] = list(b"v" * 32)
        with self.assertRaises(ValueError):
            _submitted_draft(case, contract, tampered)
        lied = json.loads(canonical(local))
        lied[1]["deviates_from_reviewed"] = True
        with self.assertRaises(ValueError):
            _submitted_draft(case, contract, lied)


class ReplayTests(unittest.TestCase):
    def provision(self, mode, failures):
        from savana_bench.protected_setup import provision_owner_episode
        contract = _TASKS[0]
        calls, stages = [], []

        class Session:
            async def close(self): pass

        class Ingress:
            async def __aenter__(self): return self
            async def __aexit__(self, *a): return False
            async def commit_text(self, text, approval): pass
            async def into_private_session(self): return Session()

        async def connect(*, bootstrap, webauthn): return Ingress()

        async def authorize(**kwargs):
            return SimpleNamespace(task_id=b"t" * 32, root_digest=b"r" * 32, application_turn=b"u" * 32,
                                   resource=b"z" * 32, command=b'{"signed":"bytes"}')

        class Operator:
            def exchange(self, request):
                calls.append(json.loads(canonical(request)))
                if request["kind"] == "compile":
                    if failures:
                        raise failures.pop(0)
                    return dict(task_id=hexd(b"t"), profile=hexd(b"f"))
                return dict(task_id=hexd(b"t"), root_digest=hexd(b"r"), profile=hexd(b"f"), run_id=hexd(b"n"))

        class Broker:
            async def next(self): return "bootstrap"

        deployment = dict(application_turn=hexd(b"u"), planner=hexd(b"p"), store=hexd(b"s"),
                          destination_digest=hexd(b"d"),
                          descriptors={contract.tool: hexd(b"x"), "savana.final_result_release": hexd(b"y")})
        with patch("savana.owner_ingress.connect", connect), \
             patch("savana_bench.protected_setup.authorize_and_prepare", authorize):
            asyncio.run(provision_owner_episode(contract=contract, deployment=deployment, broker=Broker(),
                operator=Operator(), progress=stages.append, consent=lambda r: True, operator_mode=mode))
        return calls, stages

    def test_untrusted_plan_gets_one_exact_replay_of_a_kernel_non_confirmation(self):
        calls, stages = self.provision("forward_untrusted_plan", [OperatorNotConfirmed("kernel")])
        compiles = [c for c in calls if c["kind"] == "compile"]
        self.assertEqual(len(compiles), 2)
        self.assertEqual(compiles[0], compiles[1])
        self.assertEqual(compiles[0]["mode"], "forward_untrusted_plan")
        self.assertIn("operator_compile_replay", stages)
        with self.assertRaises(OperatorNotConfirmed):
            self.provision("forward_untrusted_plan", [OperatorNotConfirmed("kernel"), OperatorNotConfirmed("kernel")])

    def test_no_replay_for_reviewed_plans_or_operator_failures(self):
        for mode, stage in (("reviewed", "kernel"), ("forward_untrusted_plan", "operator"),
                            ("forward_untrusted_plan", None)):
            failures = [OperatorNotConfirmed(stage)]
            with self.assertRaises(OperatorNotConfirmed):
                self.provision(mode, failures)
            self.assertEqual(failures, [])

    def test_operator_reports_kernel_non_confirmation_as_its_own_stage(self):
        class Artifact:
            def canonical_bytes(self): return b"canonical"
            def signing_digest(self): return b"d" * 32

        async def refuse(raw, signature):
            raise RuntimeError("management result not confirmed")
        with tempfile.TemporaryDirectory() as tmp:
            op = FiniteOperator({}, Ed25519PrivateKey.generate(), tmp)
            with patch("savana.managed_admin.prepare_artifact", return_value=Artifact()), \
                 patch("savana.managed_admin.submit_signed", side_effect=refuse):
                with self.assertRaises(KernelNotConfirmed):
                    op._submit(Path(tmp), "compile", {})
            # The exact signed bytes were retained before submission.
            self.assertTrue((Path(tmp) / "compile.json").exists())
            self.assertFalse((Path(tmp) / "compile.receipt.json").exists())
        self.assertEqual(OperatorNotConfirmed("kernel").stage, "kernel")
        self.assertIsNone(OperatorNotConfirmed("anything").stage)
        self.assertEqual(str(OperatorNotConfirmed("kernel")), "operator_not_confirmed_preserve_task")


if __name__ == "__main__":
    unittest.main()
