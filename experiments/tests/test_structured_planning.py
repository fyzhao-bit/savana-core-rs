"""A program through agentd's structured planning and back: the catalog, the
conversion, the private mapper, the graph-only planner prompt and its
DeepSeek client (fake transport only), the lowering and the owner's review
again, and the whole path through the agentd example over real mutual TLS.
Never kernel, model or benchmark evidence."""
import json
import os
from pathlib import Path
import random
import unittest

from agentdojo.task_suite.load_suites import get_suite
from savana_bench.agentdojo_provider import canonical
from savana_bench.drafted_tasks import EXTRACT_TOOL, ProgramRefused
from savana_bench.structured_planning import (
    DRAFTED_INTENT, DRAFTED_TEMPLATE, LIMITS, OP, DeepSeekStructuralPlanner, NullPlanner, ProgramMapper,
    StructuredError, StructuredSession, eval_catalog, exposure, lower_plan, order_reply, plan_program, planner_body,
    planner_view, program_to_workflow, review, sentinels, template_intent, topological, write_reordered)
from savana_bench.structured_templates import load_registry
from savana_bench.structured_wire import (
    EFFECTS, ROLES, StructuralNode, StructuralRequest, decode_mapper_request, decode_order, decode_ordered_plan,
    encode_structural_request, mapper_request, validate_order)

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = Path(os.environ.get("SAVANA_STRUCTURED_EXAMPLE")
               or Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "debug" / "examples"
               / "structured_plan_eval")
SALT = bytes(range(32))
REGISTRY = load_registry()
CATALOGS = {}


def catalog(suite):
    return CATALOGS.setdefault(suite, eval_catalog(suite))


def text(value):
    return {"text": value}


# slack user_task_3: read a page, extract a summary, post it.
SUMMARY = {"steps": [
    {"tool": "dojo.web.get", "args": {"url": text("www.informations.com")}},
    {"tool": EXTRACT_TOOL, "source": 1, "args": {"target": text("dojo.slack.send_channel.text")}},
    {"tool": "dojo.slack.send_channel", "args": {"channel": text("general"), "text": {"from": 2}}},
]}


def anonymise(workflow, draw):
    """agentd's relabel: fresh ids, nodes and edges sorted by id, arities
    from the edges -> (request, id -> ordinal)."""
    ids = {node.ordinal: bytes(draw.randrange(1, 256) for _ in range(16)) for node in workflow.nodes}
    incoming = {o: sum(1 for _a, b in workflow.edges if b == o) for o in ids}
    outgoing = {o: sum(1 for a, _b in workflow.edges if a == o) for o in ids}
    nodes = sorted((StructuralNode(ids[n.ordinal], n.role, n.effects, incoming[n.ordinal], outgoing[n.ordinal])
                    for n in workflow.nodes), key=lambda n: n.id)
    edges = sorted((ids[a], ids[b]) for a, b in workflow.edges)
    return StructuralRequest(tuple(nodes), tuple(edges)), {v: k for k, v in ids.items()}


def decoded(conversion, order):
    """The plan agentd decodes for `order` (mapped ordinals)."""
    workflow = conversion.workflow
    labels = {bytes([o]) * 16: o for o in range(1, len(workflow.nodes) + 1)}
    return decode_order(workflow.nodes, workflow.edges, [bytes([o]) * 16 for o in order], labels)


def random_order(workflow, draw):
    remaining, order = {n.ordinal for n in workflow.nodes}, []
    while remaining:
        choice = draw.choice(sorted(o for o in remaining if all(a in order for a, b in workflow.edges if b == o)))
        order.append(choice)
        remaining.remove(choice)
    return order


class CatalogAndConversionTests(unittest.TestCase):
    def test_catalog_gives_every_operation_an_id_role_and_effect(self):
        tools = catalog("slack")
        self.assertEqual(len({(t.tool_class, t.action) for t in tools}), len(tools))
        by_operation = {t.operation: t for t in tools}
        self.assertEqual((by_operation["dojo.web.get"].role, by_operation["dojo.web.get"].effects),
                         (ROLES["source"], EFFECTS["read"]))
        self.assertEqual((by_operation[EXTRACT_TOOL].role, by_operation[EXTRACT_TOOL].effects),
                         (ROLES["transform"], EFFECTS["send"]))
        self.assertEqual(by_operation["dojo.compute.table"].role, ROLES["transform"])
        self.assertEqual((by_operation["dojo.slack.send_channel"].role, by_operation["dojo.slack.invite"].effects),
                         (ROLES["sink"], EFFECTS["send"]))
        self.assertEqual(by_operation["dojo.slack.remove"].effects, EFFECTS["delete"])
        self.assertTrue(all(t.description for t in tools))
        self.assertNotIn("dojo.email.send", by_operation)

    def test_one_node_per_step_op_and_literal_slots_and_the_last_step_stays_last(self):
        conversion = program_to_workflow(SUMMARY, catalog("slack"), salt=SALT)
        nodes = conversion.workflow.nodes
        self.assertEqual([n.ordinal for n in nodes], [1, 2, 3])
        self.assertEqual([[name for name, _ref in n.bindings] for n in nodes],
                         [[OP, "url"], [OP, "target"], ["channel", OP]])
        self.assertEqual(conversion.workflow.edges, ((1, 2), (2, 3)))
        self.assertEqual(conversion.data_edges, {(1, 2), (2, 3)})
        self.assertEqual(sorted(conversion.ops.values()), [1, 2, 3])
        self.assertEqual(sorted((s, n, v) for s, n, v in conversion.literals.values()),
                         [(1, "url", text("www.informations.com")), (2, "target", text("dojo.slack.send_channel.text")),
                          (3, "channel", text("general"))])
        self.assertEqual(list(conversion.slots), sorted(conversion.slots, key=lambda s: s.ref))
        # A step that feeds nothing gets an edge into the last step.
        lone = {"steps": [SUMMARY["steps"][0], {"tool": "dojo.slack.channels", "args": {}}, *SUMMARY["steps"][1:]]}
        lone["steps"][2] = dict(lone["steps"][2], source=1)
        lone["steps"][3] = {"tool": "dojo.slack.send_channel", "args": {"channel": text("general"), "text": {"from": 3}}}
        edges = program_to_workflow(lone, catalog("slack"), salt=SALT).workflow.edges
        self.assertEqual(edges, ((1, 3), (2, 4), (3, 4)))

    def test_slots_are_keyed_by_the_salt_and_bad_programs_are_refused(self):
        same = program_to_workflow(SUMMARY, catalog("slack"), salt=SALT)
        self.assertEqual(program_to_workflow(SUMMARY, catalog("slack"), salt=SALT).slots, same.slots)
        other = program_to_workflow(SUMMARY, catalog("slack"), salt=bytes(32))
        self.assertFalse({s.ref for s in other.slots} & {s.ref for s in same.slots})
        forward = {"steps": [dict(SUMMARY["steps"][1], source=2), SUMMARY["steps"][0]]}
        for program in (forward, {"steps": [{"tool": "dojo.email.send", "args": {}}]},
                        {"steps": [{"tool": "dojo.web.get", "args": {"op": text("x")}}]}, {"steps": []},
                        {"steps": [SUMMARY["steps"][0]] * 9}):
            with self.assertRaises(StructuredError):
                program_to_workflow(program, catalog("slack"), salt=SALT)

    def test_intent_is_fixed_by_the_writes_or_constant_for_drafts(self):
        self.assertEqual(template_intent(SUMMARY), "send_message")
        self.assertEqual(template_intent({"steps": SUMMARY["steps"][:2]}), "search")
        self.assertEqual(template_intent({"steps": [{"tool": "dojo.slack.remove", "args": {"user": text("x")}}]}),
                         "store_record")
        drafted = ProgramMapper(SUMMARY, catalog("slack"), source="drafted", template=5, salt=SALT)
        self.assertEqual((drafted.intent, drafted.template), (DRAFTED_INTENT, DRAFTED_TEMPLATE))

    def test_the_mapper_answers_only_agentds_exact_request_once(self):
        mapper = ProgramMapper(SUMMARY, catalog("slack"), source="template", template=3, salt=SALT)
        job = mapper.job("j")
        request = decode_mapper_request(mapper.request_bytes)
        self.assertEqual(request, mapper_request(
            template=3, intent=1, actions=sorted({t["action"] for t in job["catalog"]}),
            slots=mapper.conversion.slots, relations=(), limits=LIMITS,
            active=[(t["class"], t["action"]) for t in job["catalog"]], tools=[t.wire() for t in catalog("slack")]))
        self.assertEqual((job["template"], job["intent"], job["limits"]), (3, "send_message", [8, 8, 16, 65536]))
        with self.assertRaises(StructuredError):
            mapper(mapper.request_bytes + b"\x00")
        fresh = ProgramMapper(SUMMARY, catalog("slack"), source="template", template=3, salt=SALT)
        self.assertEqual(fresh(fresh.request_bytes), fresh.response)
        with self.assertRaises(StructuredError):
            fresh(fresh.request_bytes)


class LoweringTests(unittest.TestCase):
    def test_every_registered_template_reviews_under_random_valid_orders(self):
        draw = random.Random(20261012)
        changed = 0
        for item in REGISTRY["templates"]:
            conversion = program_to_workflow(item["program"], catalog(item["suite"]), salt=SALT)
            identity = lower_plan(conversion, decoded(conversion, range(1, len(item["program"]["steps"]) + 1)))
            self.assertEqual(canonical(identity), canonical(item["program"]), item["user"])
            for _ in range(3):
                order = random_order(conversion.workflow, draw)
                changed += order != sorted(order)
                lowered = lower_plan(conversion, decoded(conversion, order))
                self.assertEqual(lowered["steps"][-1]["tool"], item["program"]["steps"][-1]["tool"])
                review(lowered, suite=item["suite"], user=item["user"])
        self.assertGreater(changed, 50)

    def test_a_plan_that_does_not_match_the_mapping_is_refused(self):
        program = {"steps": [SUMMARY["steps"][0], {"tool": "dojo.slack.channels", "args": {}},
                             dict(SUMMARY["steps"][1], args=dict(SUMMARY["steps"][1]["args"], context={"from": 2})),
                             dict(SUMMARY["steps"][2], args=dict(SUMMARY["steps"][2]["args"], text={"from": 3}))]}
        conversion = program_to_workflow(program, catalog("slack"), salt=SALT)
        steps = decoded(conversion, [2, 1, 3, 4])
        lowered = lower_plan(conversion, steps)
        self.assertEqual([s["tool"] for s in lowered["steps"]],
                         ["dojo.slack.channels", "dojo.web.get", EXTRACT_TOOL, "dojo.slack.send_channel"])
        self.assertEqual((lowered["steps"][2]["source"], lowered["steps"][2]["args"]["context"]), (2, {"from": 1}))
        self.assertEqual(lowered["steps"][3]["args"]["text"], {"from": 3})
        literal = conversion.workflow.nodes[0].bindings
        stolen = steps[2]._replace(bindings=tuple(sorted((name, ref) for name, ref in steps[2].bindings
                                                         if name == OP) + [("target", literal[1][1])]))
        for bad in (steps[:3], [steps[0]] * 4, [steps[0]._replace(tool_class=999)] + list(steps[1:]),
                    [steps[0], steps[1], stolen, steps[3]],
                    [steps[0], steps[1], steps[2]._replace(dependencies=(1,)), steps[3]],
                    [steps[0], steps[1], steps[3]._replace(ordinal=3), steps[2]._replace(ordinal=4)]):
            with self.assertRaises(StructuredError):
                lower_plan(conversion, bad)

    def test_write_reordering_is_flagged(self):
        program = {"steps": [{"tool": "dojo.slack.send_channel", "args": {"channel": text("general"),
                                                                        "text": text("hi")}},
                             {"tool": "dojo.slack.read_channel", "args": {"channel": text("general")}},
                             {"tool": EXTRACT_TOOL, "source": 2, "args": {"target": text("answer")}}]}
        conversion = program_to_workflow(program, catalog("slack"), salt=SALT)
        self.assertFalse(write_reordered(conversion, [1, 2, 3]))
        self.assertTrue(write_reordered(conversion, [2, 1, 3]))


class PlannerPromptTests(unittest.TestCase):
    def test_the_prompt_is_a_pure_function_of_the_anonymised_graph(self):
        draw = random.Random(3)
        first = program_to_workflow(SUMMARY, catalog("slack"), salt=SALT)
        other = {"steps": [{"tool": "dojo.slack.read_inbox", "args": {"user": text("Bob")}},
                           {"tool": EXTRACT_TOOL, "source": 1, "args": {"target": text("dojo.slack.send_dm.text")}},
                           {"tool": "dojo.slack.send_dm", "args": {"recipient": text("Alice"), "text": {"from": 2}}}]}
        second = program_to_workflow(other, catalog("slack"), salt=bytes(32))
        state = draw.getstate()
        request, _ = anonymise(first.workflow, draw)
        draw.setstate(state)
        again, _ = anonymise(second.workflow, draw)
        self.assertEqual(encode_structural_request(request), encode_structural_request(again))
        self.assertEqual(planner_body(request, model="m"), planner_body(again, model="m"))
        labels, view = planner_view(request)
        self.assertEqual(sorted(labels.values()), ["n1", "n2", "n3"])
        self.assertEqual(set(json.loads(view)), {"nodes", "edges"})

    def test_no_planner_byte_carries_a_value_name_or_description(self):
        draw = random.Random(11)
        scanned = 0
        for item in REGISTRY["templates"]:
            tools = catalog(item["suite"])
            conversion = program_to_workflow(item["program"], tools, salt=SALT)
            request, _ = anonymise(conversion.workflow, draw)
            prompt = get_suite("v1.2.2", item["suite"]).get_user_task_by_id(item["user"]).PROMPT
            secret = sentinels(item["program"], prompt, tools)
            self.assertTrue(any(t.operation in secret for t in tools))
            body = planner_body(request, model="deepseek-flash")[1]
            view = planner_view(request)[1].encode()
            self.assertEqual(exposure((encode_structural_request(request), view), secret), [], item["user"])
            scanned += len(secret)
            self.assertEqual(exposure((body,), [item["program"]["steps"][0]["tool"]]), [])
        self.assertGreater(scanned, 1000)


class FakeConnection:
    def __init__(self, reply, record, status=200):
        self.reply, self.record, self.status, self.closed = reply, record, status, False

    def request(self, method, path, body=None, headers=None):
        self.record.append((method, path, body, headers))
        if isinstance(self.reply, Exception):
            raise self.reply

    def getresponse(self):
        connection = self

        class Response:
            status = connection.status

            def read(self, size):
                return connection.reply
        return Response()

    def close(self):
        self.closed = True


def model_reply(content, **changes):
    value = dict(model="deepseek-flash", choices=[dict(finish_reason="stop", message=dict(
        role="assistant", content=content))], usage=dict(prompt_tokens=10, completion_tokens=5))
    value.update(changes)
    return json.dumps(value).encode()


class DeepSeekPlannerTests(unittest.TestCase):
    KEY = "sk-synthetic-structural-credential"

    def setUp(self):
        conversion = program_to_workflow(SUMMARY, catalog("slack"), salt=SALT)
        self.request, _ = anonymise(conversion.workflow, random.Random(5))
        self.body = encode_structural_request(self.request)
        self.labels = planner_view(self.request)[0]
        self.order = [self.labels[i] for i in topological(self.request)]
        self.record, self.connections = [], []

    def planner(self, reply, *, status=200, max_calls=2):
        def connect(timeout):
            self.assertEqual(timeout, 25.0)
            connection = FakeConnection(reply, self.record, status)
            self.connections.append(connection)
            return connection
        return DeepSeekStructuralPlanner(self.KEY, max_calls=max_calls, connect=connect)

    def test_graph_only_request_key_only_in_the_header(self):
        planner = self.planner(model_reply(json.dumps({"order": self.order})))
        reply = planner(self.body)
        self.assertEqual(decode_ordered_plan(reply), tuple(topological(self.request)))
        (method, path, body, headers), = self.record
        self.assertEqual((method, path), ("POST", "/chat/completions"))
        self.assertEqual(body, planner_body(self.request, model="deepseek-flash")[1])
        sent = json.loads(body)
        self.assertEqual((sent["temperature"], sent["thinking"], sent["stream"]), (0, {"type": "disabled"}, False))
        self.assertEqual(headers["Authorization"], "Bearer " + self.KEY)
        for leak in (repr(planner), json.dumps(planner.log), body.decode()):
            self.assertNotIn(self.KEY, leak)
        self.assertEqual((planner.calls, planner.prompt_tokens, planner.completion_tokens), (1, 10, 5))
        self.assertTrue(self.connections[0].closed)

    def test_failure_is_never_retried_and_the_budget_is_hard(self):
        for planner in (self.planner(b"", status=500), self.planner(ConnectionError(self.KEY)),
                        self.planner(model_reply("{}", model="other")),
                        self.planner(model_reply("{}", choices=[dict(finish_reason="length", message=dict(
                            role="assistant", content="{}"))]))):
            before = len(self.connections)
            with self.assertRaises(RuntimeError) as caught:
                planner(self.body)
            self.assertNotIn(self.KEY, repr(caught.exception) + str(caught.exception.__cause__))
            self.assertIsNone(caught.exception.__cause__)
            self.assertEqual((len(self.connections) - before, planner.calls), (1, 1))
        planner = self.planner(model_reply(json.dumps({"order": self.order})), max_calls=1)
        planner(self.body)
        with self.assertRaisesRegex(RuntimeError, "structural_planner_budget"):
            planner(self.body)
        closed = self.planner(model_reply(json.dumps({"order": self.order})))
        closed.close()
        count = len(self.connections)
        with self.assertRaisesRegex(RuntimeError, "structural_planner_budget"):
            closed(self.body)
        self.assertEqual(len(self.connections), count)

    def test_labels_are_translated_and_judged_by_agentd(self):
        duplicate = order_reply(json.dumps({"order": [self.order[0]] * 3}), self.labels)
        with self.assertRaises(Exception):
            validate_order(self.request, decode_ordered_plan(duplicate))
        for content, code in ((json.dumps({"order": ["n9"]}), "planner_label"), ("not json", "planner_reply"),
                              (json.dumps({"order": []}), "planner_reply"), (json.dumps([1]), "planner_reply")):
            with self.assertRaisesRegex(StructuredError, code):
                order_reply(content, self.labels)


EXAMPLE_READY = unittest.skipUnless(EXAMPLE.is_file(), "build the structured_plan_eval example first")


@EXAMPLE_READY
class PipelineTests(unittest.TestCase):
    """Templates through the real agentd example and endpoints."""

    def run_template(self, planner, index=0):
        item = REGISTRY["templates"][index]
        session = StructuredSession(EXAMPLE, planner)
        self.addCleanup(session.close)
        mapper = ProgramMapper(item["program"], catalog(item["suite"]), source="template", template=index + 1)
        return item, mapper, plan_program(session, mapper, job_id=f"t-{index}", suite=item["suite"], user=item["user"])

    def longest(self):
        return max(range(len(REGISTRY["templates"])), key=lambda i: len(REGISTRY["templates"][i]["program"]["steps"]))

    def test_a_template_is_planned_lowered_and_reviewed(self):
        item, mapper, result = self.run_template(NullPlanner(), self.longest())
        self.assertEqual(result["outcome"], "planned", result)
        self.assertEqual(result["contract"].task_id, item["user"])
        self.assertEqual(mapper.calls, 1)
        prompt = get_suite("v1.2.2", item["suite"]).get_user_task_by_id(item["user"]).PROMPT
        self.assertEqual(exposure((bytes.fromhex(result["planner_request"]),),
                                  sentinels(item["program"], prompt, mapper.catalog)), [])

    def test_a_model_planner_reply_is_judged_by_agentd(self):
        def deepseek(order):
            def model(timeout):
                class Connection(FakeConnection):
                    def request(self, method, path, body=None, headers=None):
                        view = json.loads(json.loads(body)["messages"][1]["content"])
                        self.reply = model_reply(json.dumps({"order": order(view)}))
                return Connection(None, [])
            return DeepSeekStructuralPlanner("synthetic", max_calls=1, connect=model)

        def forward(view):
            done, order = set(), []
            while len(order) < len(view["nodes"]):
                for node in view["nodes"]:
                    label = node["label"]
                    if label not in done and all(a in done for a, b in view["edges"] if b == label):
                        done.add(label)
                        order.append(label)
            return order
        index = self.longest()
        cases = ((forward, "planned", None), (lambda v: forward(v)[::-1], "planner_invalid", "planner_invalid_plan"),
                 (lambda v: [forward(v)[0]] * len(v["nodes"]), "planner_invalid", "planner_invalid_plan"),
                 (lambda v: forward(v)[:-1] + ["n99"], "planner_invalid", "planner_unavailable"))
        for order, outcome, error in cases:
            _item, _mapper, result = self.run_template(deepseek(order), index)
            self.assertEqual((result["outcome"], result["error"]), (outcome, error))
            if outcome != "planned":
                self.assertIsNone(result["plan"])

    def test_a_mapper_that_is_not_asked_its_own_request_maps_nothing(self):
        item = REGISTRY["templates"][0]
        session = StructuredSession(EXAMPLE, NullPlanner())
        self.addCleanup(session.close)
        mapper = ProgramMapper(item["program"], catalog(item["suite"]), source="template", template=1)
        mapper.request_bytes = b"\x80"
        result = plan_program(session, mapper, job_id="mismatch", suite=item["suite"], user=item["user"])
        self.assertEqual((result["outcome"], result["error"], result["planner_request"]),
                         ("mapper_failed", "mapper_unavailable", None))
        self.assertEqual(session.planner.calls, 0)

    def test_a_lowered_program_the_review_refuses_never_plans(self):
        # slack user_task_1's request never states the address SUMMARY fetches.
        with self.assertRaises(ProgramRefused):
            review(SUMMARY, suite="slack", user="user_task_1")
        session = StructuredSession(EXAMPLE, NullPlanner())
        self.addCleanup(session.close)
        mapper = ProgramMapper(SUMMARY, catalog("slack"), source="drafted")
        result = plan_program(session, mapper, job_id="refused", suite="slack", user="user_task_1")
        self.assertEqual((result["outcome"], result["lowering_error"]), ("lowering_failed", "review_literal_not_owner_text"))
        self.assertEqual(canonical(result["lowered"]), canonical(SUMMARY))
        self.assertEqual(plan_program(session, ProgramMapper(SUMMARY, catalog("slack"), source="drafted"),
                                      job_id="accepted", suite="slack", user="user_task_3")["outcome"], "planned")


if __name__ == "__main__":
    unittest.main()
