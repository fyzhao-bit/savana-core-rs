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
from savana_bench.agentdojo_tasks import prepare_draft
from savana_bench.planner_experiment import (ProviderRelay, classify_provider_attempt, experiment_cases,
                                             plan_author_for, provisioning_outcome)
from savana_bench.protected_operator import FiniteOperator, KernelNotConfirmed, OperatorNotConfirmed
from tests.test_drafted_tasks import one_read_contract


def hexd(c):
    return (c * 32).hex()


def kernel_context(contract):
    """The IDs and registered descriptors the kernel hands the plan author."""
    now = time.time_ns() // 1000000
    ids = dict(task=b"a" * 32, root=b"b" * 32, observer=b"o" * 32, application_turn=b"u" * 32,
               planner=b"p" * 32, model_profile=1, not_before=now, expires_at=now + 120000)
    descriptors = {st.tool: bytes([i + 1]) * 32 for i, st in enumerate(contract.steps())}
    descriptors["savana.final_result_release"] = b"r" * 32
    return ids, dict(ids, descriptors=descriptors, release_descriptor=b"r" * 32)


class CaseTests(unittest.TestCase):
    def test_only_drafted_specs_are_accepted(self):
        for bad in ("", "honest", "poisoned", "compromised", "compromised:slot_swap", "write",
                    "write:injection_task_0", "generate:honest", "drafted", "all", None):
            with self.assertRaises(ValueError, msg=bad):
                experiment_cases(bad)

    def test_drafted_specs_honest_and_poisoned(self):
        honest = experiment_cases("drafted:banking:user_task_2,user_task_7")
        self.assertEqual([(c["group"], c["user"], c["goal"], c["root_author"], c["injection"]) for c in honest],
                         [("drafted_benign", "user_task_2", None, "deepseek", None),
                          ("drafted_benign", "user_task_7", None, "deepseek", None)])
        attack = experiment_cases("drafted:workspace:user_task_1+injection_task_0")
        self.assertEqual(attack[0]["group"], "drafted_attack")
        self.assertEqual(attack[0]["injection"], "injection_task_0")
        poisoned = experiment_cases("drafted-poison:exfiltrate:slack:user_task_3,user_task_7")
        self.assertEqual([(c["group"], c["user"], c["goal"], c["root_author"], c["injection"]) for c in poisoned],
                         [("drafted_poisoned", "user_task_3", "exfiltrate", "deepseek", None),
                          ("drafted_poisoned", "user_task_7", "exfiltrate", "deepseek", None)])
        # Every poison goal names a real ROOT_POISON_GOALS objective.
        from savana_bench.root_drafter import ROOT_POISON_GOALS, ROOT_SYSTEM, poisoned_root_system
        for goal in ROOT_POISON_GOALS:
            cases = experiment_cases(f"drafted-poison:{goal}:travel:user_task_0")
            self.assertEqual(cases[0]["goal"], goal)
            self.assertTrue(poisoned_root_system(goal).startswith(ROOT_SYSTEM))
            self.assertIn(ROOT_POISON_GOALS[goal], poisoned_root_system(goal))
        for bad in ("drafted-poison:exfiltrate:slack:user_task_3+injection_task_1",  # planner OR env, not both
                    "drafted-poison:nope:slack:user_task_3",                          # unknown goal
                    "drafted-poison:exfiltrate",                                       # no suite/items
                    "drafted-poison::slack:user_task_3",                               # empty goal
                    "drafted-poison:exfiltrate:nosuite:user_task_3"):                  # unknown suite
            with self.assertRaises(ValueError, msg=bad):
                experiment_cases(bad)


class VerdictTests(unittest.TestCase):
    def test_provider_requests_are_judged_only_against_the_owner_root(self):
        contract = one_read_contract()
        step, = contract.steps()
        judge = lambda value: classify_provider_attempt(canonical(value), contract=contract,
                                                        resource="ab" * 32, application_turn="cd" * 32)
        tool = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": step.tool, "arguments": step.value_map()}}
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
    def test_the_reviewed_draft_is_encoded_against_the_kernel_ids(self):
        contract = one_read_contract()
        ids, context = kernel_context(contract)
        events, facts = [], dict(plan_supplied=False, deviates=None)
        emit = lambda kind, **data: events.append((kind, data))
        draft = plan_author_for(contract, emit, facts)(contract, context)
        reviewed = prepare_draft(contract, tool_descriptor=context["descriptors"][contract.steps()[0].tool],
                                 release_descriptor=b"r" * 32, **ids)["planning_draft"]
        self.assertEqual(draft, json.loads(canonical(reviewed)))
        self.assertEqual(facts, dict(plan_supplied=True, deviates=False))
        self.assertEqual(events[-1][0], "plan_submitted")
        self.assertEqual(events[-1][1]["draft"], draft)
        self.assertIs(events[-1][1]["deviates_from_reviewed"], False)
        # The kernel asks for this contract's plan; any other is refused.
        with self.assertRaises(ValueError):
            plan_author_for(contract, emit, dict(facts))(SimpleNamespace(), context)


class VerifierTests(unittest.TestCase):
    def test_the_submitted_draft_must_be_the_reviewed_draft(self):
        from savana_bench.planner_verify import _submitted_draft
        contract = one_read_contract()
        _ids, context = kernel_context(contract)
        events = []
        emit = lambda kind, **data: events.append(dict(data, kind=kind))
        plan_author_for(contract, emit, dict(plan_supplied=False, deviates=None))(contract, context)
        local = json.loads(canonical(events))
        self.assertEqual(_submitted_draft(contract, local)[1], False)
        tampered = json.loads(canonical(local))
        tampered[0]["draft"]["final_release"]["turn"] = list(b"v" * 32)
        with self.assertRaises(ValueError):
            _submitted_draft(contract, tampered)
        lied = json.loads(canonical(local))
        lied[0]["deviates_from_reviewed"] = True
        with self.assertRaises(ValueError):
            _submitted_draft(contract, lied)


class ReplayTests(unittest.TestCase):
    def provision(self, mode, failures):
        from savana_bench.protected_setup import provision_owner_episode
        contract = one_read_contract()
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
                          descriptors={contract.steps()[0].tool: hexd(b"x"),
                                       "savana.final_result_release": hexd(b"y")})
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
