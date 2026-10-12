"""The structured-planning evaluation's runner and verifier hooks: the
registered and structured authors and the `+mapper` option (every earlier
spec unchanged), the manifest provenance, and the offline verifier
re-deriving a structured episode from synthetic evidence. agentd's half of a
job is played in process by the codecs test_structured_example checks against
agentd itself. Never kernel, model or benchmark evidence."""
import copy
import hashlib
import json
import unittest

from savana_bench.agentdojo_provider import canonical
from savana_bench.planner_experiment import DEFINITIVE, STRUCTURED_REFUSALS, experiment_cases, structured_provenance
from savana_bench.planner_verify import _drafted_contract
from savana_bench.structured_planning import (
    LIMITS, PLANNER_SYSTEM, DeepSeekStructuralPlanner, ProgramMapper, eval_catalog, evidence, plan_program, review)
from savana_bench.structured_templates import load_registry, program_text, registry_sha256, template_number
from savana_bench.structured_wire import (
    PlannerPlan, StructuralNode, StructuralRequest, WireError, decode_order, decode_ordered_plan, encode_plan,
    encode_structural_request, validate_order)
from tests.test_structured_planning import FakeConnection, model_reply

REGISTRY = load_registry()


def literal_strings(program):
    return [v["text"] for step in program["steps"] for v in step["args"].values()
            if type(v) is dict and type(v.get("text")) is str and 6 <= len(v["text"].encode()) <= 16]


# A registered slack task with at least three steps and an owner literal.
ITEM = next(item for item in REGISTRY["templates"] if item["suite"] == "slack"
            and len(item["program"]["steps"]) >= 3 and literal_strings(item["program"]))


def forward(view):
    done, order = set(), []
    while len(order) < len(view["nodes"]):
        for node in view["nodes"]:
            label = node["label"]
            if label not in done and all(a in done for a, b in view["edges"] if b == label):
                done.add(label)
                order.append(label)
    return order


def model(order):
    """The DeepSeek structural planner behind a fake transport answering `order(view)`."""
    def connect(timeout):
        class Connection(FakeConnection):
            def request(self, method, path, body=None, headers=None):
                view = json.loads(json.loads(body)["messages"][1]["content"])
                self.reply = model_reply(json.dumps({"order": order(view)}))
        return Connection(None, [])
    return DeepSeekStructuralPlanner("synthetic", max_calls=4, connect=connect)


class FakeAgentd:
    """agentd's half of one job as the example reports it: the mapper call,
    the relabel (here: given ids), the planner call and the decode."""

    def __init__(self, planner, ids=None, mapper_fails=False):
        self.planner, self.ids, self.mapper_fails = planner, ids, mapper_fails

    def run(self, mapper, *, job_id, boundary="private"):
        reply = dict(job=job_id, status="refused", error=None, mapper_response=None, planner_request=None,
                     planner_response=None, plan=None, steps=None)
        if self.mapper_fails:
            return dict(reply, error="mapper_invalid_workflow")
        response = mapper(mapper.request_bytes)
        workflow = mapper.conversion.workflow
        ids = self.ids or {n.ordinal: hashlib.sha256(b"id%d" % n.ordinal).digest()[:16] for n in workflow.nodes}
        nodes = sorted((StructuralNode(ids[n.ordinal], n.role, n.effects,
                                       sum(b == n.ordinal for _a, b in workflow.edges),
                                       sum(a == n.ordinal for a, _b in workflow.edges)) for n in workflow.nodes),
                       key=lambda n: n.id)
        request = StructuralRequest(tuple(nodes), tuple(sorted((ids[a], ids[b]) for a, b in workflow.edges)))
        body = encode_structural_request(request)
        reply.update(mapper_response=response.hex(), planner_request=body.hex())
        try:
            answer = self.planner(body)
        except Exception:
            return dict(reply, error="planner_unavailable")
        try:
            ordered = validate_order(request, decode_ordered_plan(answer))
        except WireError:
            return dict(reply, error="planner_invalid_plan")
        steps = decode_order(workflow.nodes, workflow.edges, ordered, {v: k for k, v in ids.items()})
        return dict(reply, status="accepted", planner_response=answer.hex(),
                    plan=encode_plan(PlannerPlan(b"\x07" * 32, steps)).hex(),
                    steps=[{"ordinal": s.ordinal, "action": s.action, "class": s.tool_class,
                            "bindings": [[n, r.hex()] for n, r in s.bindings], "dependencies": list(s.dependencies)}
                           for s in steps])


def case(spec_tail="", item=ITEM):
    return experiment_cases(f"drafted+author=structured{spec_tail}:{item['suite']}:{item['user']}")[0]


def episode(planner, agentd=None, item=ITEM):
    """The evidence a runner records for one arm-T structured episode."""
    the_case = case(item=item)
    text = program_text(REGISTRY, item["suite"], item["user"])
    drafted = dict(kind="root_drafted", episode=0, attempt=1, program_text=text, request_sha256=None,
                   response_sha256=hashlib.sha256(text.encode()).hexdigest())
    reviewed = review(json.loads(text), suite=item["suite"], user=item["user"])
    mapper = ProgramMapper(json.loads(reviewed.program), eval_catalog(item["suite"]), source="template",
                           template=template_number(REGISTRY, item["suite"], item["user"]))
    calls = len(planner.log)
    planned = plan_program(agentd or FakeAgentd(planner), mapper, job_id="episode-0", suite=item["suite"],
                           user=item["user"])
    event = json.loads(canonical(dict(kind="structured_planned", episode=0,
                                      **evidence(planned, planner.log[calls:]))))
    return the_case, [drafted, event], planned


class SpecTests(unittest.TestCase):
    def test_registered_and_structured_authors_and_the_mapper_option(self):
        user = ITEM["user"]
        registered, = experiment_cases(f"drafted+author=registered:slack:{user}")
        plain, = experiment_cases(f"drafted:slack:{user}")
        self.assertEqual(dict(registered, root_author="deepseek"), plain)
        self.assertNotIn("mapper", registered)
        self.assertEqual((case()["root_author"], case()["mapper"]), ("structured", "template"))
        drafted, = experiment_cases("drafted+author=structured+mapper=deepseek+drafts=3:banking:user_task_0")
        self.assertEqual((drafted["mapper"], drafted["max_drafts"]), ("deepseek", 3))
        excluded = REGISTRY["excluded"][0]
        for bad in (f"drafted+mapper=template:slack:{user}", f"drafted+author=registered+drafts=2:slack:{user}",
                    f"drafted+author=structured+mapper=nope:slack:{user}",
                    f"drafted+author=fixed+mapper=template:slack:{user}",
                    f"drafted+author=registered:{excluded['suite']}:{excluded['user']}",
                    f"drafted+author=structured:{excluded['suite']}:{excluded['user']}",
                    f"drafted-poison+author=structured:exfiltrate:slack:{user}"):
            with self.assertRaises(ValueError, msg=bad):
                experiment_cases(bad)
        self.assertEqual(set(STRUCTURED_REFUSALS) - set(DEFINITIVE), set())

    def test_only_registered_and_structured_runs_carry_provenance(self):
        self.assertEqual(structured_provenance(experiment_cases(f"drafted:slack:{ITEM['user']}")), {})
        self.assertEqual(structured_provenance(experiment_cases(f"drafted+author=registered:slack:{ITEM['user']}")),
                         dict(structured_templates_sha256=registry_sha256()))
        provenance = structured_provenance([case()])
        self.assertEqual(provenance["structured_planner_system_sha256"],
                         hashlib.sha256(PLANNER_SYSTEM.encode()).hexdigest())
        self.assertEqual((provenance["structured_limits"], provenance["structured_example_sha256"]),
                         (list(LIMITS), None))


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.case, self.local, self.planned = episode(model(forward))

    def test_a_structured_episode_is_rederived_from_its_evidence(self):
        self.assertEqual(self.planned["outcome"], "planned")
        contract = _drafted_contract(self.case, self.local, dict(outcome="published", drafts=1))
        self.assertEqual(contract.digest(), self.planned["contract"].digest())
        self.assertEqual(json.loads(contract.program), self.planned["lowered"])
        self.assertEqual(len(self.local[1]["planner_calls"]), 1)

    def test_tampered_evidence_is_refused(self):
        event = self.local[1]

        def changed(**fields):
            return [self.local[0], dict(copy.deepcopy(event), **fields)]
        call = dict(event["planner_calls"][0])
        steps = event["lowered"]["steps"]
        mutations = {
            "salt": changed(salt="11" * 32),
            "mapper_response": changed(mapper_response=event["mapper_response"][:-2] + "00"),
            "intent": changed(intent="store_record"),
            "prompt": changed(planner_calls=[dict(call, prompt_sha256="0" * 64)]),
            "model_reply": changed(planner_calls=[dict(call, content=json.dumps({"order": ["n1"]}))]),
            "order": changed(order=list(reversed(event["order"]))),
            "lowered": changed(lowered=dict(event["lowered"], steps=steps[:-1] + [dict(steps[-1], tool="dojo.web.get")])),
            "no_model_call": changed(planner_calls=[]),
        }
        for name, local in mutations.items():
            with self.subTest(name), self.assertRaises(ValueError):
                _drafted_contract(self.case, local, dict(outcome="published", drafts=1))
        for outcome in ("planner_invalid", "mapper_failed", "program_refused"):
            with self.subTest(outcome), self.assertRaises(ValueError):
                _drafted_contract(self.case, self.local, dict(outcome=outcome, drafts=1, refusal="x"))
        text = dict(self.local[0], program_text=self.local[0]["program_text"].replace("}", " }", 1))
        with self.assertRaisesRegex(ValueError, "registered_program_evidence"):
            _drafted_contract(self.case, [text, event], dict(outcome="published", drafts=1))

    def test_a_planner_byte_that_carries_an_owner_value_is_refused(self):
        literal = literal_strings(ITEM["program"])[0].encode().ljust(16, b"\x01")
        ids = {n: hashlib.sha256(b"x%d" % n).digest()[:16] for n in range(1, len(ITEM["program"]["steps"]) + 1)}
        ids[1] = literal
        planner = model(forward)
        the_case, local, planned = episode(planner, FakeAgentd(planner, ids=ids))
        self.assertEqual(planned["outcome"], "planned")
        with self.assertRaisesRegex(ValueError, "structured_planner_exposure"):
            _drafted_contract(the_case, local, dict(outcome="published", drafts=1))

    def test_each_refusal_is_checked_against_what_the_planner_replied(self):
        for order, error in ((lambda view: forward(view)[::-1], "planner_invalid_plan"),
                             (lambda view: forward(view)[:-1] + ["n99"], "planner_unavailable")):
            the_case, local, planned = episode(model(order))
            self.assertEqual((planned["outcome"], planned["error"]), ("planner_invalid", error))
            row = dict(outcome="planner_invalid", drafts=1)
            self.assertIsNone(_drafted_contract(the_case, local, row))
            other = "planner_unavailable" if error == "planner_invalid_plan" else "planner_invalid_plan"
            with self.assertRaisesRegex(ValueError, "structured_planner_refusal"):
                _drafted_contract(the_case, [local[0], dict(local[1], error=other)], row)
        planner = model(forward)
        the_case, local, planned = episode(planner, FakeAgentd(planner, mapper_fails=True))
        self.assertEqual((planned["outcome"], local[1]["planner_calls"]), ("mapper_failed", []))
        self.assertIsNone(_drafted_contract(the_case, local, dict(outcome="mapper_failed", drafts=1)))
        with self.assertRaises(ValueError):
            _drafted_contract(the_case, local, dict(outcome="published", drafts=1))


if __name__ == "__main__":
    unittest.main()
