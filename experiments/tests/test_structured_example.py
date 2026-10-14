"""The Python stand-ins against agentd itself, through the example driver
(`cargo build -p savana-agentd --features test-support --example
structured_plan_eval`): agentd's own encoders and decoders on the same
objects (byte-exact, and the same verdict on mutated bodies), and the real
pipeline over real mutual TLS, including the refusals of agentd's e2e test.
Never kernel, model or benchmark evidence."""
import os
from pathlib import Path
import random
import unittest

from savana_bench.structured_wire import (
    CARDINALITIES, CONFIDENTIALITIES, INTENTS, MAPPER_PATH, PLANNER_PATH, ROLES, CatalogTool, EphemeralPki,
    ExampleProcess, MappedNode, OneShotServer, PlanStep, PlannerPlan, Relation, Slot, StructuralNode,
    StructuralRequest, WireError, Workflow, decode_mapper_request, decode_ordered_plan, decode_plan,
    decode_structural_request, decode_workflow, encode_mapper_request, encode_ordered_plan, encode_plan,
    encode_structural_request, encode_workflow, mapper_request)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = Path(os.environ.get("SAVANA_STRUCTURED_EXAMPLE")
               or Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "debug" / "examples"
               / "structured_plan_eval")
NEEDS_EXAMPLE = unittest.skipUnless(EXAMPLE.is_file(), "build the structured_plan_eval example first")
MAPPER_HOST, PLANNER_HOST = "mapper.structured.test", "planner.structured.test"
NAMES = {table: {v: k for k, v in values.items()} for table, values in
         (("role", ROLES), ("intent", INTENTS), ("cardinality", CARDINALITIES),
          ("confidentiality", CONFIDENTIALITIES))}


def ref(byte):
    return bytes([byte]) * 16


def slot_spec(slot):
    return dict(ref=slot.ref.hex(), kind=slot.kind, cardinality=NAMES["cardinality"][slot.cardinality],
                confidentiality=NAMES["confidentiality"][slot.confidentiality])


def tool_spec(tool):
    return {"class": tool.tool_class, "action": tool.action, "role": NAMES["role"][tool.role],
            "effects": tool.effects, "name": tool.name, "description": tool.description}


def request_spec(*, template, intent, actions, slots, relations, limits, active, tools):
    return dict(template=template, intent=NAMES["intent"][intent], allowed_actions=list(actions),
                slots=[slot_spec(s) for s in slots],
                relations=[dict(relation=r.relation, left=r.left.hex(), right=r.right.hex()) for r in relations],
                limits=list(limits), active=[list(pair) for pair in active], catalog=[tool_spec(t) for t in tools])


TOOLS = (CatalogTool(200, 20, 3, 0x10, "sink_tool", "send transformed records"),
         CatalogTool(100, 10, 1, 0x01, "source_tool", "read source records"),
         CatalogTool(4294967295, 4294967295, 2, 0x21, "transform\u00e9", "d" * 300),
         CatalogTool(150, 15, 3, 0x46, "inactive", "never offered"))
REQUEST = dict(template=4294967295, intent=4, actions=(10, 15, 20, 4294967295),
               slots=(Slot(ref(0x01), 1, 1, 1), Slot(ref(0xA1), 70000, 4, 2), Slot(ref(0xB2), 2, 2, 1)),
               relations=(Relation(1, ref(0xA1), ref(0xB2)), Relation(300, ref(0x01), ref(0xA1))),
               limits=(8, 8, 16, 65536), active=((100, 10), (200, 20), (4294967295, 4294967295)), tools=TOOLS)


@NEEDS_EXAMPLE
class VectorTests(unittest.TestCase):
    """agentd's own codecs, through the example's vectors mode."""

    @classmethod
    def setUpClass(cls):
        cls.example = ExampleProcess(EXAMPLE, {"mode": "vectors"})

    @classmethod
    def tearDownClass(cls):
        cls.example.close()

    def rust(self, kind, **fields):
        reply = self.example.request(dict(fields, vector=kind))
        self.assertNotIn("error", reply, kind)
        return bytes.fromhex(reply["cbor"])

    def accepted(self, kind, body, **fields):
        return self.example.request(dict(fields, vector="decode_" + kind, cbor=body.hex()))["accepted"]

    def structural(self):
        a, b, c, d = (StructuralNode(ref(x), r, e, i, o) for x, r, e, i, o in
                      ((0x10, 1, 0x01, 0, 2), (0xF0, 2, 0x10, 1, 1), (0x20, 2, 0x01, 1, 1), (0x30, 3, 0x46, 2, 0)))
        return StructuralRequest((a, b, c, d), ((a.id, b.id), (a.id, c.id), (b.id, d.id), (c.id, d.id)))

    def workflow(self):
        sink = MappedNode(4, 200, 20, (("a", ref(0xB2)), ("op", ref(0x01))), 3, 0x10)
        source = MappedNode(90, 100, 10, (("z", ref(0xA1)),), 1, 0x01)
        middle = MappedNode(300, 4294967295, 4294967295, (), 2, 0x21)
        return Workflow((sink, source, middle), ((90, 4), (90, 300), (300, 4)))

    def plan(self):
        return PlannerPlan(b"\xcc" * 32, (PlanStep(1, 10, 100, (("op", ref(0x01)), ("z", ref(0xA1))), ()),
                                          PlanStep(2, 4294967295, 4294967295, (), (1,)),
                                          PlanStep(3, 20, 200, (("a" * 128, ref(0xB2)),), (1, 2))))

    def test_encoders_are_byte_identical(self):
        request = self.structural()
        nodes = [dict(id=n.id.hex(), role=n.role, effects=n.effects, **{"in": n.in_arity, "out": n.out_arity})
                 for n in request.nodes]
        self.assertEqual(self.rust("structural_request", nodes=nodes,
                                   edges=[[a.hex(), b.hex()] for a, b in request.edges]),
                         encode_structural_request(request))
        ids = [n.id for n in request.nodes]
        self.assertEqual(self.rust("ordered_plan", ids=[i.hex() for i in ids]), encode_ordered_plan(ids))
        mapper = mapper_request(**REQUEST)
        self.assertEqual([t.name for t in mapper.tools], ["source_tool", "sink_tool", "transform\u00e9"])
        self.assertEqual(self.rust("mapper_request", **request_spec(**REQUEST)), encode_mapper_request(mapper))
        workflow = self.workflow()
        canonical = Workflow(tuple(sorted(workflow.nodes, key=lambda n: n.ordinal)), tuple(sorted(workflow.edges)))
        nodes = [{"ordinal": n.ordinal, "class": n.tool_class, "action": n.action, "role": n.role,
                  "effects": n.effects, "bindings": [[name, r.hex()] for name, r in n.bindings]}
                 for n in workflow.nodes]
        self.assertEqual(self.rust("mapped_workflow", request=request_spec(**REQUEST), nodes=nodes,
                                   edges=[list(e) for e in workflow.edges]), encode_workflow(canonical))
        plan = self.plan()
        steps = [{"ordinal": s.ordinal, "action": s.action, "class": s.tool_class,
                  "bindings": [[name, r.hex()] for name, r in s.bindings], "dependencies": list(s.dependencies)}
                 for s in plan.steps]
        self.assertEqual(self.rust("planner_plan", nonce=plan.nonce.hex(), steps=steps), encode_plan(plan))

    def test_decoders_agree_on_valid_and_mutated_bodies(self):
        mapper = mapper_request(**REQUEST)
        workflow = self.workflow()
        canonical = Workflow(tuple(sorted(workflow.nodes, key=lambda n: n.ordinal)), tuple(sorted(workflow.edges)))
        cases = (("structural_request", encode_structural_request(self.structural()), decode_structural_request, {}),
                 ("ordered_plan", encode_ordered_plan([ref(1), ref(2), ref(3)]), decode_ordered_plan, {}),
                 ("mapper_request", encode_mapper_request(mapper), decode_mapper_request, {}),
                 ("mapped_workflow", encode_workflow(canonical), lambda b: decode_workflow(b, mapper),
                  dict(request=request_spec(**REQUEST))),
                 ("planner_plan", encode_plan(self.plan()), decode_plan, {}))
        draw = random.Random(20261012)
        disagreements, verdicts = [], set()
        for kind, body, decode, extra in cases:
            mutants = [body]
            for _ in range(60):
                at = draw.randrange(len(body))
                mutants.append(draw.choice((
                    body[:at] + bytes([draw.randrange(256)]) + body[at + 1:],
                    body[:at] + body[at + 1:],
                    body[:at] + bytes([draw.randrange(256)]) + body[at:],
                    body[:at] + bytes([body[at] ^ (1 << draw.randrange(8))]) + body[at + 1:])))
            for mutant in mutants:
                try:
                    decode(mutant)
                    python = True
                except WireError:
                    python = False
                verdicts.add(python)
                if python != self.accepted(kind, mutant, **extra):
                    disagreements.append((kind, mutant.hex()))
        self.assertEqual(disagreements, [])
        self.assertEqual(verdicts, {True, False})


class Endpoints:
    """One run's CA, a mapper and a planner endpoint with swappable handlers,
    and the example configured against them."""

    def __init__(self, *, ceiling="private_only"):
        self.pki = EphemeralPki([MAPPER_HOST, PLANNER_HOST])
        self.mapper_handler = self.planner_handler = None
        self.bodies = {"mapper": [], "planner": []}

        def handler(name):
            def call(body):
                self.bodies[name].append(body)
                return getattr(self, name + "_handler")(body)
            return call
        self.mapper = OneShotServer(context=self.pki.server_context(MAPPER_HOST), client_pin=self.pki.client_pin,
                                    host=MAPPER_HOST, path=MAPPER_PATH, handler=handler("mapper")).start()
        self.planner = OneShotServer(context=self.pki.server_context(PLANNER_HOST), client_pin=self.pki.client_pin,
                                     host=PLANNER_HOST, path=PLANNER_PATH, handler=handler("planner")).start()
        self.example = ExampleProcess(EXAMPLE, self.config(ceiling))

    def config(self, ceiling):
        def endpoint(host, server):
            return dict(host=host, address="%s:%d" % server.address, spki_sha256=self.pki.server_pins[host].hex())
        return dict(ca_certificate=self.pki.ca_der.hex(), client_certificate=self.pki.client_der.hex(),
                    client_private_key=self.pki.client_key_der.hex(), ceiling=ceiling,
                    mapper=endpoint(MAPPER_HOST, self.mapper), planner=endpoint(PLANNER_HOST, self.planner))

    def close(self):
        self.example.close()
        self.mapper.close()
        self.planner.close()


SOURCE = CatalogTool(100, 10, 1, 0x01, "customer_lookup", "query private customer records")
SINK = CatalogTool(200, 20, 3, 0x10, "account_notice", "send records to destination")


JOB_REQUEST = dict(template=7, intent=2, actions=(10, 20), slots=(Slot(ref(0xA1), 1, 1, 1), Slot(ref(0xB2), 2, 1, 2)),
                   relations=(), limits=(8, 8, 16, 65536), active=((100, 10), (200, 20)), tools=(SOURCE, SINK))


def two_step_job(job, *, active=None, boundary="private"):
    """A read then a send: one slot each, one edge."""
    spec = request_spec(**dict(JOB_REQUEST, active=active or JOB_REQUEST["active"]))
    return dict(spec, job=job, boundary=boundary, exchange_ms=10000)


def two_step_workflow(source=SOURCE):
    return Workflow((MappedNode(1, source.tool_class, source.action, (("op", ref(0xA1)),), source.role,
                                source.effects),
                     MappedNode(2, 200, 20, (("op", ref(0xB2)),), 3, 0x10)), ((1, 2),))


@NEEDS_EXAMPLE
class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.endpoints = Endpoints()
        self.addCleanup(self.endpoints.close)

    def run_job(self, job, *, mapper=None, planner=None):
        endpoints = self.endpoints
        endpoints.mapper_handler = mapper or (lambda body: encode_workflow(two_step_workflow()))

        def forward(body):
            request = decode_structural_request(body)
            return encode_ordered_plan([request.edges[0][0], request.edges[0][1]])
        endpoints.planner_handler = planner or forward
        reply = endpoints.example.request(job)
        self.assertTrue(endpoints.mapper.settled() and endpoints.planner.settled())
        return reply

    def test_a_job_is_mapped_anonymised_ordered_and_decoded(self):
        reply = self.run_job(two_step_job("accepted"))
        self.assertEqual((reply["status"], reply["error"]), ("accepted", None))
        mapper_body, = self.endpoints.bodies["mapper"]
        planner_body, = self.endpoints.bodies["planner"]
        self.assertEqual(bytes.fromhex(reply["mapper_request"]), mapper_body)
        self.assertEqual(bytes.fromhex(reply["planner_request"]), planner_body)
        # The mapper sees the request agentd projects; Python re-encodes it exactly.
        request = decode_mapper_request(mapper_body)
        self.assertEqual(encode_mapper_request(mapper_request(**JOB_REQUEST)), mapper_body)
        self.assertEqual(bytes.fromhex(reply["mapper_response"]), encode_workflow(two_step_workflow()))
        self.assertEqual(decode_workflow(bytes.fromhex(reply["mapper_response"]), request), two_step_workflow())
        # The planner sees roles, effects, arities and fresh ids only.
        graph = decode_structural_request(planner_body)
        self.assertEqual(sorted((n.role, n.effects, n.in_arity, n.out_arity) for n in graph.nodes),
                         [(1, 1, 0, 1), (3, 0x10, 1, 0)])
        for secret in (b"customer_lookup", b"account_notice", b"query private", ref(0xA1), ref(0xB2)):
            self.assertNotIn(secret, planner_body)
        plan = decode_plan(bytes.fromhex(reply["plan"]))
        self.assertEqual([(s.ordinal, s.tool_class, s.bindings, s.dependencies) for s in plan.steps],
                         [(1, 100, (("op", ref(0xA1)),), ()), (2, 200, (("op", ref(0xB2)),), (1,))])
        self.assertEqual(reply["steps"], [{"ordinal": s.ordinal, "action": s.action, "class": s.tool_class,
                                           "bindings": [[n, r.hex()] for n, r in s.bindings],
                                           "dependencies": list(s.dependencies)} for s in plan.steps])
        self.assertEqual(decode_ordered_plan(bytes.fromhex(reply["planner_response"])),
                         (graph.edges[0][0], graph.edges[0][1]))

    def test_one_issuer_never_reuses_planner_ids(self):
        first = self.run_job(two_step_job("first"))
        second = self.run_job(two_step_job("second"))
        ids = [{n.id for n in decode_structural_request(bytes.fromhex(r["planner_request"])).nodes}
               for r in (first, second)]
        self.assertEqual(ids[0] & ids[1], set())

    def test_the_child_starts_with_an_empty_environment(self):
        self.assertEqual(Path(f"/proc/{self.endpoints.example.pid}/environ").read_bytes(), b"")

    def test_an_inactive_tool_is_refused_before_the_planner(self):
        inactive = CatalogTool(999, 10, 1, 0x01, "x", "y")
        reply = self.run_job(two_step_job("inactive"),
                             mapper=lambda body: encode_workflow(two_step_workflow(source=inactive)))
        self.assertEqual((reply["status"], reply["error"]), ("refused", "mapper_invalid_workflow"))
        self.assertEqual((self.endpoints.planner.connections, reply["plan"]), (0, None))
        # A tool the session has not activated is never offered to the mapper.
        reply = self.run_job(two_step_job("narrowed", active=((100, 10),)))
        self.assertEqual(reply["error"], "mapper_invalid_workflow")
        self.assertNotIn(b"account_notice", self.endpoints.bodies["mapper"][-1])

    def test_a_planner_reply_that_is_not_a_forward_permutation_is_refused_before_commit(self):
        def reply_with(order):
            def planner(body):
                request = decode_structural_request(body)
                return encode_ordered_plan(order(request.edges[0]))
            return planner
        for name, order in (("backward", lambda e: [e[1], e[0]]), ("duplicate", lambda e: [e[0], e[0]]),
                            ("missing", lambda e: [e[0]]), ("unknown", lambda e: [e[0], ref(0xEE)])):
            reply = self.run_job(two_step_job(name), planner=reply_with(order))
            self.assertEqual((reply["status"], reply["error"], reply["plan"]),
                             ("refused", "planner_invalid_plan", None), name)

    def test_unavailable_endpoints_and_boundaries_are_fixed_codes(self):
        def fail(body):
            raise RuntimeError("no reply")
        self.assertEqual(self.run_job(two_step_job("mapper-down"), mapper=fail)["error"], "mapper_unavailable")
        self.assertEqual(self.run_job(two_step_job("planner-down"), planner=fail)["error"], "planner_unavailable")
        connections = self.endpoints.mapper.connections
        reply = self.run_job(two_step_job("third-party", boundary="third_party"))
        self.assertEqual((reply["error"], reply["mapper_request"]), ("mapper_boundary_denied", None))
        self.assertEqual(self.endpoints.mapper.connections, connections)
        self.assertEqual(self.endpoints.example.request({"job": "x", "template": 0})["error"], "job_invalid")


@NEEDS_EXAMPLE
class ConfigTests(unittest.TestCase):
    def test_a_bad_configuration_never_reports_ready(self):
        with self.assertRaises(RuntimeError):
            ExampleProcess(EXAMPLE, {"ceiling": "private_only"})


if __name__ == "__main__":
    unittest.main()
