"""A trusted-set origin (U7, `+owner=set`): the owner signs its directory, as
exact values, into every destination edge data fills; the kernel endorses a
member itself, and this software owner approves a data-chosen destination only
where the kernel's display says it is one."""
import json
import importlib.util
import unittest
from types import SimpleNamespace

from savana_bench.agentdojo_tasks import edge_candidates, edge_document, register_drafted, signed_edge
from savana_bench.benchmark_consent import FiniteConsent, _displayed_edges, _roles
from savana_bench.owner_directory import directory_members, directory_sha256, owner_directory
from savana_bench.planner_experiment import destination_candidates, directory_provenance, experiment_cases
from tests.test_floor_experiment import FETCH_FROM_MESSAGE, PAY_BILL, review

NEEDS_AGENTDOJO = unittest.skipUnless(importlib.util.find_spec("agentdojo"), "install the explicit AgentDojo test extra")

ATTACKER_IBAN = "US133000000121212121212"


@NEEDS_AGENTDOJO
class MembersTests(unittest.TestCase):
    def test_the_signed_members_are_the_directory_as_exact_values(self):
        slack = directory_members("slack")
        self.assertIn("Alice", slack)
        self.assertNotIn("alice", slack)
        self.assertEqual(list(slack), sorted(slack, key=str.encode))
        for suite in ("workspace", "banking", "slack", "travel"):
            members = directory_members(suite)
            self.assertEqual({m.casefold() for m in members}, set(owner_directory(suite)), suite)
            self.assertTrue(all(m == m.strip() and len(m.encode()) <= 512 for m in members), suite)
        with self.assertRaises(ValueError):
            directory_members("shopping")


class ReviewTests(unittest.TestCase):
    @NEEDS_AGENTDOJO
    def test_a_data_chosen_destination_carries_the_signed_set(self):
        members = directory_members("banking")
        contract = review("banking", "user_task_0", PAY_BILL, derived_destinations=True,
                          destination_candidates=members)
        pay = contract.steps()[5]
        edges = {edge[0]: edge for edge in pay.derived}
        self.assertEqual(edge_candidates(edges["recipient"]), members)
        # Only whom the call reaches is bounded; the amount, subject and date are not destinations.
        self.assertEqual({f for f, e in edges.items() if edge_candidates(e) is not None}, {"recipient"})
        self.assertEqual(signed_edge(edges["recipient"])["candidates"], list(members))
        self.assertEqual(edge_document(edges["recipient"])["candidates"], list(members))
        self.assertNotIn("candidates", signed_edge(edges["amount"]))
        # A fetched address is not a destination of a write: no set, so it stays data's choice.
        fetch = review("slack", "user_task_1", FETCH_FROM_MESSAGE, derived_destinations=True,
                       destination_candidates=directory_members("slack"))
        self.assertIsNone(edge_candidates(fetch.steps()[2].derived[0]))

    @NEEDS_AGENTDOJO
    def test_a_set_needs_derived_destinations_and_members(self):
        for options in (dict(destination_candidates=("a",)),
                        dict(derived_destinations=True, destination_candidates=())):
            with self.assertRaises(ValueError):
                review("banking", "user_task_0", PAY_BILL, **options)

    def test_an_edge_set_is_canonical_and_bounded(self):
        edge = ("recipient", 2, ("x",), 32, None)
        self.assertEqual(edge_candidates(edge + (("a", "b"),)), ("a", "b"))
        for members in (("b", "a"), ("a", "a"), (), ("a" * 33,), (" a",), ("a\nb",), ["a"]):
            with self.assertRaises(ValueError, msg=members):
                edge_candidates(edge + (members,))
        with self.assertRaises(ValueError):
            edge_candidates(("amount", 2, ("x",), 32, ("add_cents", 100), ("a",)))


@NEEDS_AGENTDOJO
class SetOwnerTests(unittest.TestCase):
    def _consent(self, events):
        contract = register_drafted(review("banking", "user_task_0", PAY_BILL, derived_destinations=True,
                                           destination_candidates=directory_members("banking")))
        consent = FiniteConsent(contract, "ab" * 32, lambda kind, **kw: events.append((kind, kw)), candidates=True)
        consent.stage, consent.action = "tool_execution", 5
        consent.task, consent.authorization = "cd" * 32, "ef" * 32
        consent.clauses = [dict(clause_id=n, alternatives=[dict(descriptor_digest=str(n) * 64)]) for n in range(1, 8)]
        consent.profiles = {str(n) * 64: dict(operation=step.tool) for n, step in enumerate(contract.steps(), 1)}
        return contract, consent

    def _pay(self, contract, recipient, member):
        step = contract.steps()[5]
        _payload, resource, destination = _roles(step)
        arguments = dict(step.value_map(), recipient=recipient, amount="98.70", subject="Car Rental",
                         date="2022-01-01")
        request = dict(jsonrpc="2.0", id="step-1", method="tools/call", params=dict(name=step.tool, arguments=arguments))
        shown = _displayed_edges(step)
        shown = {f: {k: v for k, v in e.items() if v is not None} for f, e in shown.items()}
        shown["recipient"]["in_candidates"] = member
        display = dict(rendering_schema=3, authorization_id="ef" * 32, authorization_revision=1, task="cd" * 32,
                       principal="ab" * 32, clause_id=6, alternative_index=0, descriptor_digest="6" * 64,
                       operation="dojo.bank.send_money", effect="Send", magnitude=1, attempts_used=0,
                       attempts_after_prepare=1, maximum_attempts=1, magnitude_charged=0, magnitude_after_prepare=1,
                       maximum_single_magnitude=1, total_magnitude_budget=1,
                       requires_verified_success_of_clauses=[1, 2, 3, 4, 5],
                       no_effect_magnitude_refund_permitted=False, exact_business_request=request,
                       derived_fields=shown, resource=arguments[resource], destination=arguments[destination])
        return SimpleNamespace(purpose="tool_execution", display=json.dumps(display))

    def test_the_kernels_member_verdict_decides(self):
        events = []
        contract, consent = self._consent(events)
        self.assertTrue(consent(self._pay(contract, "GB29NWBK60161331926819", True)))
        self.assertEqual(events[-1][1]["policy"], "finite_write_preconsent_v1+candidate_destination")
        events = []
        contract, consent = self._consent(events)
        with self.assertRaises(ValueError) as caught:
            consent(self._pay(contract, ATTACKER_IBAN, False))
        self.assertEqual(str(caught.exception), "consent_destination_not_in_candidates")
        self.assertEqual(events[-1][1]["reason"], "consent_destination_not_in_candidates")

    def test_a_display_without_the_signed_set_is_refused(self):
        events = []
        contract, consent = self._consent(events)
        request = self._pay(contract, "GB29NWBK60161331926819", True)
        display = json.loads(request.display)
        del display["derived_fields"]["recipient"]["candidates"]
        with self.assertRaises(ValueError):
            consent(SimpleNamespace(purpose="tool_execution", display=json.dumps(display)))

    def test_a_set_owner_is_neither_strict_nor_a_directory_owner(self):
        contract = register_drafted(review("banking", "user_task_0", PAY_BILL, derived_destinations=True))
        for options in (dict(candidates=True, strict_destinations=True),
                        dict(candidates=True, directory=owner_directory("banking")), dict(candidates=1)):
            with self.assertRaises(ValueError):
                FiniteConsent(contract, "ab" * 32, lambda *a, **k: None, **options)


@NEEDS_AGENTDOJO
class OptionTests(unittest.TestCase):
    def test_a_set_owner_needs_derived_destinations_and_records_its_members(self):
        case, = experiment_cases("drafted+drafts=3+review=derived+owner=set:banking:user_task_0")
        self.assertEqual(destination_candidates(case), directory_members("banking"))
        self.assertEqual(directory_provenance([case]),
                         dict(owner_candidates_sha256={"banking": directory_sha256(directory_members("banking"))}))
        self.assertIsNone(destination_candidates(dict(case, owner="directory")))
        with self.assertRaises(ValueError):
            experiment_cases("drafted+owner=set:banking:user_task_0")


if __name__ == "__main__":
    unittest.main()
