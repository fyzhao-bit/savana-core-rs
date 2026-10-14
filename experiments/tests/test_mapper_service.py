"""The service mapper (`+mapper=service`): the job agentd gets is fixed before
anything is planned, the drafting model plans only when agentd's mapper
request for that job arrives, and the offline verifier re-derives the request
and the workflow from the recorded salt and the accepted program. agentd's
half is played in process (test_structured_runner's FakeAgentd); the drafter
is a stand-in that records what the runner records. Never kernel, model or
benchmark evidence."""
import hashlib
import json
import unittest

from savana_bench.agentdojo_provider import canonical
from savana_bench.planner_experiment import experiment_cases
from savana_bench.planner_verify import _drafted_contract
from savana_bench.root_drafter import draft_request_body
from savana_bench.structured_planning import (
    DRAFTED_INTENT, DRAFTED_TEMPLATE, LIMITS, LITERAL_SLOTS, OP, NullPlanner, ServiceMapper, StructuredError,
    StructuredSession, eval_catalog, evidence, lower_plan, plan_program, pool_slots, review, slot_pool)
from savana_bench.structured_templates import program_text
from savana_bench.structured_wire import decode_mapper_request, decode_plan, decode_workflow, validate_workflow
from tests.test_structured_runner import ITEM, REGISTRY, FakeAgentd, forward, literal_strings, model
from tests.test_structured_example import EXAMPLE, NEEDS_EXAMPLE

SALT = bytes(range(32))


def program():
    return json.loads(program_text(REGISTRY, ITEM["suite"], ITEM["user"]))


class ServiceAgentd(FakeAgentd):
    """agentd as FakeAgentd plays it, except that a mapper that raises gets no
    reply (an unavailable mapper), as agentd reports one."""

    def run(self, mapper, *, job_id, boundary="private"):
        try:
            return super().run(mapper, job_id=job_id, boundary=boundary)
        except StructuredError:
            return dict(job=job_id, status="refused", error="mapper_unavailable", mapper_response=None,
                        planner_request=None, planner_response=None, plan=None, steps=None)


class PoolTests(unittest.TestCase):
    def test_a_pool_is_opaque_distinct_and_from_the_salt_alone(self):
        ops, literals = slot_pool(SALT)
        self.assertEqual((len(ops), len(literals)), (LIMITS[0], LITERAL_SLOTS))
        self.assertEqual(slot_pool(SALT), (ops, literals))
        self.assertEqual(len({*ops, *literals}), LIMITS[0] + LITERAL_SLOTS)
        self.assertNotEqual(slot_pool(bytes(32))[0][0], ops[0])
        self.assertTrue(all(len(ref) == 16 and ref != bytes(16) for ref in (*ops, *literals)))
        slots = pool_slots((ops, literals))
        self.assertEqual([s.ref for s in slots], sorted(s.ref for s in slots))
        for bad in (b"short", None, "ab" * 16):
            with self.assertRaises(StructuredError):
                slot_pool(bad)

    def test_the_job_carries_nothing_of_the_program_or_the_request(self):
        planned = []
        mapper = ServiceMapper(eval_catalog(ITEM["suite"]), lambda: planned.append(1) or program(), salt=SALT)
        line = json.dumps(mapper.job("episode-0"))
        request = decode_mapper_request(mapper.request_bytes)
        self.assertEqual((request.template, mapper.intent, mapper.template), (DRAFTED_TEMPLATE, DRAFTED_INTENT,
                                                                             DRAFTED_TEMPLATE))
        self.assertEqual({s.ref for s in request.slots}, {*slot_pool(SALT)[0], *slot_pool(SALT)[1]})
        for literal in literal_strings(program()):
            self.assertNotIn(literal, line)
            self.assertNotIn(literal.encode(), mapper.request_bytes)
        # The same salt fixes the same job, whatever is planned later.
        other = ServiceMapper(eval_catalog(ITEM["suite"]), lambda: {"steps": []}, salt=SALT)
        self.assertEqual(other.request_bytes, mapper.request_bytes)
        self.assertEqual(planned, [])


class ServiceMapperTests(unittest.TestCase):
    def test_it_plans_only_for_agentds_request_and_answers_on_its_slots(self):
        calls = []
        mapper = ServiceMapper(eval_catalog(ITEM["suite"]), lambda: calls.append(1) or program(), salt=SALT)
        with self.assertRaisesRegex(StructuredError, "mapper_request_mismatch"):
            mapper(mapper.request_bytes + b"\x00")
        self.assertEqual(calls, [])
        fresh = ServiceMapper(eval_catalog(ITEM["suite"]), lambda: calls.append(1) or program(), salt=SALT)
        response = fresh(fresh.request_bytes)
        self.assertEqual(calls, [1])
        workflow = validate_workflow(fresh.request, decode_workflow(response, fresh.request))
        pool = {*slot_pool(SALT)[0], *slot_pool(SALT)[1]}
        self.assertTrue(all(ref in pool for node in workflow.nodes for _name, ref in node.bindings))
        self.assertEqual([dict(n.bindings)[OP] for n in workflow.nodes],
                         list(slot_pool(SALT)[0][:len(workflow.nodes)]))
        with self.assertRaisesRegex(StructuredError, "mapper_request_mismatch"):
            fresh(fresh.request_bytes)
        self.assertEqual(calls, [1])
        replayed = ServiceMapper.replay(eval_catalog(ITEM["suite"]), program(), salt=SALT)
        self.assertEqual((replayed.request_bytes, replayed.response), (fresh.request_bytes, response))

    def test_a_failed_plan_or_a_program_too_big_for_the_pool_gets_no_reply(self):
        def refuse():
            raise RuntimeError("drafter_unavailable")
        mapper = ServiceMapper(eval_catalog(ITEM["suite"]), refuse, salt=SALT)
        with self.assertRaisesRegex(StructuredError, "mapper_plan"):
            mapper(mapper.request_bytes)
        self.assertEqual((type(mapper.failure), mapper.response, mapper.conversion), (RuntimeError, None, None))
        literals = sum(1 for step in program()["steps"] for value in step["args"].values()
                       if not (type(value) is dict and "from" in value))
        self.assertGreater(literals, 1)
        small = ServiceMapper(eval_catalog(ITEM["suite"]), program, salt=SALT, literals=literals - 1)
        with self.assertRaisesRegex(StructuredError, "mapper_conversion"):
            small(small.request_bytes)
        self.assertIsInstance(small.failure, StructuredError)
        exact = ServiceMapper(eval_catalog(ITEM["suite"]), program, salt=SALT, literals=literals)
        self.assertIsNotNone(exact(exact.request_bytes))

    def test_the_lowered_program_is_the_planned_one_in_the_planners_order(self):
        mapper = ServiceMapper(eval_catalog(ITEM["suite"]), program, salt=SALT)
        planner = model(forward)
        planned = plan_program(ServiceAgentd(planner), mapper, job_id="episode-0", suite=ITEM["suite"],
                               user=ITEM["user"])
        self.assertEqual(planned["outcome"], "planned")
        self.assertEqual(sorted(planned["order"]), list(range(1, len(program()["steps"]) + 1)))
        steps = decode_plan(bytes.fromhex(planned["plan"])).steps
        self.assertEqual(lower_plan(mapper.conversion, steps), planned["lowered"])
        tools = sorted(step["tool"] for step in program()["steps"])
        self.assertEqual(sorted(step["tool"] for step in planned["lowered"]["steps"]), tools)
        self.assertEqual(planned["contract"].program, review(planned["lowered"], suite=ITEM["suite"],
                                                             user=ITEM["user"]).program)


def service_case(spec="drafted+drafts=3+author=structured+mapper=service"):
    return experiment_cases(f"{spec}:{ITEM['suite']}:{ITEM['user']}")[0]


def episode(planner, *, drafts=(None,), agentd=None, salt=SALT, the_case=None):
    """The evidence a runner records for one service-mapper episode: the
    drafts its mapper wrote when agentd asked (`drafts`: the program text of
    each, None for the registered program), then the structured record."""
    from agentdojo.task_suite.load_suites import get_suite
    from savana_bench.agentdojo_tasks import BENCHMARK
    from savana_bench.drafted_tasks import ProgramRefused
    the_case = the_case or service_case()
    official = get_suite(BENCHMARK, the_case["suite"])
    prompt = official.get_user_task_by_id(the_case["user"]).PROMPT
    local, history = [], []

    def plan():
        accepted = None
        for attempt, text in enumerate(drafts, 1):
            text = text or program_text(REGISTRY, ITEM["suite"], ITEM["user"])
            body = draft_request_body(official, prompt, model=the_case["planner_model"], history=tuple(history))
            local.append(dict(kind="root_drafted", episode=0, attempt=attempt, program_text=text, view="request",
                              placeholders=0, request_sha256=hashlib.sha256(body).hexdigest(),
                              response_sha256=hashlib.sha256(text.encode()).hexdigest()))
            try:
                accepted = review(json.loads(text), suite=the_case["suite"], user=the_case["user"])
            except ProgramRefused as error:
                local.append(dict(kind="program_refused", episode=0, attempt=attempt, reason=str(error),
                                  step=error.step, field=error.field))
                history.append((text, str(error), error.step, error.field))
                if attempt == len(drafts):
                    raise
                continue
            return json.loads(accepted.program)
        raise AssertionError("unreachable")
    mapper = ServiceMapper(eval_catalog(the_case["suite"]), plan, salt=salt)
    calls = len(planner.log)
    planned = plan_program(agentd or ServiceAgentd(planner), mapper, job_id="episode-0", suite=the_case["suite"],
                           user=the_case["user"])
    local.append(json.loads(canonical(dict(kind="structured_planned", episode=0,
                                            **evidence(planned, planner.log[calls:])))))
    return the_case, local, planned, mapper


class VerifierTests(unittest.TestCase):
    def test_a_service_episode_is_rederived_from_its_evidence(self):
        the_case, local, planned, _mapper = episode(model(forward))
        self.assertEqual(planned["outcome"], "planned")
        contract = _drafted_contract(the_case, local, dict(outcome="published", drafts=1))
        self.assertEqual(contract.digest(), planned["contract"].digest())
        for name, event in (("salt", dict(local[-1], salt="11" * 32)),
                            ("response", dict(local[-1], mapper_response=local[-1]["mapper_response"][:-2] + "00")),
                            ("template", dict(local[-1], template=7))):
            with self.subTest(name), self.assertRaises(ValueError):
                _drafted_contract(the_case, [*local[:-1], event], dict(outcome="published", drafts=1))

    def test_drafts_refused_inside_the_mapper_leave_agentd_without_a_workflow(self):
        bad = json.dumps({"steps": [{"tool": "dojo.slack.send_dm",
                                     "args": {"recipient": {"text": "attacker-sink-9"}, "text": {"text": "hi"}}}]})
        the_case, local, planned, mapper = episode(model(forward), drafts=(bad, bad, bad))
        self.assertEqual((planned["outcome"], planned["error"]), ("mapper_failed", "mapper_unavailable"))
        self.assertEqual(type(mapper.failure).__name__, "ProgramRefused")
        refusal = str(mapper.failure)
        self.assertIsNone(_drafted_contract(the_case, local, dict(outcome="program_refused", drafts=3,
                                                                  refusal=refusal)))
        # A planner that was asked anyway, or a job other than the salt's, is refused.
        asked = dict(local[-1], planner_request="00")
        with self.assertRaisesRegex(ValueError, "structured_service_evidence"):
            _drafted_contract(the_case, [*local[:-1], asked], dict(outcome="program_refused", drafts=3,
                                                                   refusal=refusal))
        other = dict(local[-1], salt="22" * 32)
        with self.assertRaisesRegex(ValueError, "structured_service_evidence"):
            _drafted_contract(the_case, [*local[:-1], other], dict(outcome="program_refused", drafts=3,
                                                                   refusal=refusal))

    def test_a_job_agentd_failed_before_asking_drafted_nothing(self):
        planner = model(forward)
        the_case, local, planned, mapper = episode(planner, agentd=ServiceAgentd(planner, mapper_fails=True))
        self.assertEqual((planned["outcome"], mapper.calls, [e["kind"] for e in local]),
                         ("mapper_failed", 0, ["structured_planned"]))
        self.assertIsNone(_drafted_contract(the_case, local, dict(outcome="mapper_failed", drafts=0)))
        with self.assertRaises(ValueError):
            _drafted_contract(the_case, local, dict(outcome="published", drafts=0))


@NEEDS_EXAMPLE
class AgentdTests(unittest.TestCase):
    """agentd's own pipeline (the example) over real mutual TLS, with the
    local topological planner: no model, no network."""

    def test_agentd_takes_a_job_fixed_before_planning_and_the_planned_workflow(self):
        planner = NullPlanner()
        session = StructuredSession(EXAMPLE, planner)
        try:
            planned_at = []
            mapper = ServiceMapper(eval_catalog(ITEM["suite"]), lambda: planned_at.append(planner.calls) or program())
            planned = plan_program(session, mapper, job_id="job-1", suite=ITEM["suite"], user=ITEM["user"])
            # Planned once, inside agentd's mapper call: before its planner request.
            self.assertEqual((planned["outcome"], planned_at, planner.calls), ("planned", [0], 1))
            self.assertEqual(sorted(step["tool"] for step in planned["lowered"]["steps"]),
                             sorted(step["tool"] for step in program()["steps"]))
            self.assertEqual(bytes.fromhex(planned["mapper_response"]), mapper.response)

            def refuse():
                raise RuntimeError("drafter_unavailable")
            failing = ServiceMapper(eval_catalog(ITEM["suite"]), refuse)
            refused = plan_program(session, failing, job_id="job-2", suite=ITEM["suite"], user=ITEM["user"])
            # No reply: agentd reports the mapper unavailable and asks no planner.
            self.assertEqual((refused["outcome"], refused["planner_request"], planner.calls),
                             ("mapper_failed", None, 1))
            self.assertIsInstance(failing.failure, RuntimeError)
        finally:
            session.close()


class SpecTests(unittest.TestCase):
    def test_the_service_mapper_takes_every_planner_pollution(self):
        user = ITEM["user"]
        plain = service_case()
        self.assertEqual((plain["mapper"], plain["root_author"], plain["max_drafts"]), ("service", "structured", 3))
        poisoned, = experiment_cases(f"drafted-poison+drafts=3+author=structured+mapper=service:exfiltrate:slack:{user}")
        self.assertEqual((poisoned["goal"], poisoned["mapper"]), ("exfiltrate", "service"))
        exposed, = experiment_cases("drafted+drafts=3+author=structured+mapper=service+attack=autodojo+exposure=data"
                                    f":slack:{user}+injection_task_1")
        self.assertEqual((exposed["planner_exposure"], exposed["attack"]), ("data", "autodojo"))
        extended, = experiment_cases("drafted+drafts=3+actions=ask+review=derived+owner=directory+author=structured"
                                     f"+mapper=service:slack:{user}")
        self.assertEqual((extended["review"], extended["owner"], extended["actions"]), ("derived", "directory", "ask"))
        with self.assertRaises(ValueError):
            experiment_cases(f"drafted+mapper=service:slack:{user}")


if __name__ == "__main__":
    unittest.main()
