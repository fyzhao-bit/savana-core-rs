"""agentd's private-planning wire, as a stand-in mapper and planner serve it.

agentd (crates/savana-agentd: planner_privacy.rs, mapper_client.rs,
planner_client.rs, private_model_transport.rs) posts canonical CBOR over pinned
mutual TLS, one request per connection:

    POST /savana.mapper.v2/map     MapperIntentRequestV2  -> MappedWorkflowV2
    POST /savana.planner.v2/plan   StructuralPlannerRequestV2 -> OrderedStructuralPlanV2

and commits the decoded PlannerPlanV2. This module encodes and decodes exactly
those shapes with agentd's own checks (closed lengths and tags, sorted
collections, bounds, and a byte-exact re-encode, since agentd compares bytes),
serves one request per connection with agentd's header rules and a clean
close_notify, mints a per-run CA with server and client certificates (SPKI
pins for agentd, a certificate pin for the servers), and runs the agentd
example driver (`examples/structured_plan_eval.rs`) as a child with an empty
environment. Nothing here decides anything: it is the wire only.
"""
import hashlib
import json
import os
import re
import select
import socket
import ssl
import subprocess
import threading
import time
import unicodedata
from typing import NamedTuple

from .protected_transport import _head

MAPPER_PATH = "/savana.mapper.v2/map"
PLANNER_PATH = "/savana.planner.v2/plan"
VERSION = 2
MAX_BODY = 8 * 1024 * 1024
MAX_NODES = 256
MAX_EDGES = 4096
MAX_TOOLS = 4096
MAX_RELATIONS = 512
MAX_SEMANTIC_BYTES = 1024
MAX_ARGUMENT_NAME_BYTES = 128
MAX_PLAN_ITEMS = 256
MAX_PLAN_BYTES = 8 * 1024 * 1024
ROLES = {"source": 1, "transform": 2, "sink": 3}
EFFECTS = {"read": 0x01, "create": 0x02, "update": 0x04, "delete": 0x08, "send": 0x10, "execute": 0x20,
           "final_release": 0x40}
ALL_EFFECTS = 0x7F
INTENTS = {"send_message": 1, "search": 2, "summarize_document": 3, "store_record": 4}
CARDINALITIES = {"exactly_one": 1, "zero_or_one": 2, "one_or_more": 3, "zero_or_more": 4}
CONFIDENTIALITIES = {"public_structural": 1, "confidential_abstract": 2}
ORDER_VALID_DATAFLOW = 1


class WireError(ValueError):
    """A body agentd would refuse; ``str(error)`` is a fixed code."""


class Slot(NamedTuple):
    ref: bytes
    kind: int
    cardinality: int
    confidentiality: int


class Relation(NamedTuple):
    relation: int
    left: bytes
    right: bytes


class Limits(NamedTuple):
    steps: int
    dependencies: int
    arguments: int
    plan_bytes: int


class CatalogTool(NamedTuple):
    tool_class: int
    action: int
    role: int
    effects: int
    name: str
    description: str


class MapperRequest(NamedTuple):
    template: int
    intent: int
    actions: tuple
    slots: tuple
    relations: tuple
    limits: Limits
    tools: tuple


class MappedNode(NamedTuple):
    ordinal: int
    tool_class: int
    action: int
    bindings: tuple  # ((argument name, slot ref), ...), sorted by name
    role: int
    effects: int


class Workflow(NamedTuple):
    nodes: tuple
    edges: tuple  # ((from ordinal, to ordinal), ...)


class StructuralNode(NamedTuple):
    id: bytes
    role: int
    effects: int
    in_arity: int
    out_arity: int


class StructuralRequest(NamedTuple):
    nodes: tuple
    edges: tuple  # ((from id, to id), ...)
    goal: int = ORDER_VALID_DATAFLOW


class PlanStep(NamedTuple):
    ordinal: int
    action: int
    tool_class: int
    bindings: tuple
    dependencies: tuple


class PlannerPlan(NamedTuple):
    nonce: bytes
    steps: tuple


def _fail(code):
    raise WireError(code)


# --- canonical CBOR (minicbor's shortest heads, definite lengths only) ---

def _uint(value):
    if type(value) is not int or value < 0:
        _fail("cbor_integer")
    return _head(0, value)


def _bytes(value):
    return _head(2, len(value)) + bytes(value)


def _text(value):
    raw = value.encode("utf-8")
    return _head(3, len(raw)) + raw


def _array(items):
    items = list(items)
    return _head(4, len(items)) + b"".join(items)


class _Reader:
    """Strict reader; any alternate spelling is caught by the caller's
    re-encode comparison, exactly as agentd re-encodes and compares."""

    def __init__(self, data):
        self.data, self.at = bytes(data), 0

    def _take(self, size):
        if size < 0 or self.at + size > len(self.data):
            _fail("cbor_truncated")
        value = self.data[self.at:self.at + size]
        self.at += size
        return value

    def _head(self, major):
        first = self._take(1)[0]
        if first >> 5 != major:
            _fail("cbor_type")
        info = first & 31
        if info < 24:
            return info
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        if info not in widths:
            _fail("cbor_indefinite")
        return int.from_bytes(self._take(widths[info]), "big")

    def uint(self, maximum):
        value = self._head(0)
        if value > maximum:
            _fail("cbor_integer_range")
        return value

    def array(self, maximum):
        size = self._head(4)
        if size > maximum:
            _fail("cbor_length")
        return size

    def exact_array(self, size):
        if self._head(4) != size:
            _fail("cbor_shape")

    def bytes(self, size):
        if self._head(2) != size:
            _fail("cbor_bytes")
        return self._take(size)

    def text(self, maximum):
        size = self._head(3)
        if size > maximum:
            _fail("cbor_text")
        try:
            return self._take(size).decode("utf-8")
        except UnicodeDecodeError:
            _fail("cbor_utf8")

    def end(self):
        if self.at != len(self.data):
            _fail("cbor_trailing")


def _body(data):
    if type(data) is not bytes or not 0 < len(data) <= MAX_BODY:
        _fail("body_size")
    return _Reader(data)


def _version(reader, fields):
    reader.exact_array(fields)
    if reader.uint(0xFFFF) != VERSION:
        _fail("wire_version")


def _id(reader):
    value = reader.bytes(16)
    if value == bytes(16):
        _fail("zero_id")
    return value


def _role_effects(role, effects):
    """agentd's validate_role_effect plus the closed tag and bit sets."""
    if role not in ROLES.values() or not 0 < effects <= ALL_EFFECTS:
        _fail("role_or_effect")
    if effects & EFFECTS["final_release"] and role != ROLES["sink"]:
        _fail("role_or_effect")


def _control(text):
    return any(unicodedata.category(ch) == "Cc" for ch in text)


def _argument_name(name):
    if type(name) is not str or not name or len(name.encode()) > MAX_ARGUMENT_NAME_BYTES or _control(name):
        _fail("argument_name")
    return name


_UNSAFE = {chr(c) for c in (0x00AD, 0x034F, 0x061C, 0x115F, 0x1160, 0x17B4, 0x17B5, 0xFEFF, *range(0x180B, 0x1810),
                            *range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2060, 0x2070))}


def semantic_text(value):
    """BoundedPlannerSemanticTextV2: non-empty, at most 1 KiB, NFC, no control
    or invisible formatting character."""
    if (type(value) is not str or not value or len(value.encode()) > MAX_SEMANTIC_BYTES or _control(value)
            or any(ch in _UNSAFE for ch in value) or unicodedata.normalize("NFC", value) != value):
        _fail("semantic_text")
    return value


def _acyclic(count, edges):
    incoming, adjacency = [0] * count, [[] for _ in range(count)]
    for a, b in edges:
        adjacency[a].append(b)
        incoming[b] += 1
    ready = [i for i in range(count) if not incoming[i]]
    seen = 0
    while ready:
        node = ready.pop()
        seen += 1
        for target in adjacency[node]:
            incoming[target] -= 1
            if not incoming[target]:
                ready.append(target)
    return seen == count


# --- the structural planner request and its ordered reply ---

def validate_structural(request):
    """StructuralGraphV2::new: unique ids, known endpoints, no self or
    duplicate edge, declared arities equal to the edges, acyclic."""
    nodes, edges = request.nodes, request.edges
    if not 0 < len(nodes) <= MAX_NODES or len(edges) > MAX_EDGES or request.goal != ORDER_VALID_DATAFLOW:
        _fail("graph_size")
    index = {}
    for position, node in enumerate(nodes):
        if type(node.id) is not bytes or len(node.id) != 16 or node.id == bytes(16) or node.id in index:
            _fail("graph_node")
        _role_effects(node.role, node.effects)
        index[node.id] = position
    pairs, incoming, outgoing = set(), [0] * len(nodes), [0] * len(nodes)
    for a, b in edges:
        if a not in index or b not in index or a == b or (a, b) in pairs:
            _fail("graph_edge")
        pairs.add((a, b))
        outgoing[index[a]] += 1
        incoming[index[b]] += 1
    if any(not 0 <= v <= 255 for v in incoming + outgoing) or any(
            (n.in_arity, n.out_arity) != (incoming[i], outgoing[i]) for i, n in enumerate(nodes)):
        _fail("graph_arity")
    if not _acyclic(len(nodes), [(index[a], index[b]) for a, b in edges]):
        _fail("graph_cycle")
    return request


def encode_structural_request(request):
    return _array([_uint(VERSION),
                   _array(_array([_bytes(n.id), _uint(n.role), _uint(n.effects), _uint(n.in_arity),
                                  _uint(n.out_arity)]) for n in request.nodes),
                   _array(_array([_bytes(a), _bytes(b)]) for a, b in request.edges),
                   _uint(request.goal)])


def decode_structural_request(data):
    reader = _body(data)
    _version(reader, 4)
    count = reader.array(MAX_NODES)
    if not count:
        _fail("graph_size")
    nodes = []
    for _ in range(count):
        reader.exact_array(5)
        nodes.append(StructuralNode(_id(reader), reader.uint(0xFFFF), reader.uint(0xFFFF), reader.uint(0xFF),
                                    reader.uint(0xFF)))
    edges = []
    for _ in range(reader.array(MAX_EDGES)):
        reader.exact_array(2)
        edges.append((_id(reader), _id(reader)))
    goal = reader.uint(0xFFFF)
    reader.end()
    request = validate_structural(StructuralRequest(tuple(nodes), tuple(edges), goal))
    if encode_structural_request(request) != data:
        _fail("non_canonical")
    return request


def encode_ordered_plan(ids):
    return _array([_uint(VERSION), _array(_bytes(i) for i in ids)])


def decode_ordered_plan(data):
    reader = _body(data)
    _version(reader, 2)
    ids = tuple(_id(reader) for _ in range(reader.array(MAX_NODES)))
    reader.end()
    if encode_ordered_plan(ids) != data:
        _fail("non_canonical")
    return ids


def validate_order(request, ids):
    """validate_ordered_structural_plan_v2: a complete, duplicate-free
    permutation of the request's nodes that keeps every edge forward."""
    known = {n.id for n in request.nodes}
    positions = {}
    for position, node in enumerate(ids):
        if node not in known or node in positions:
            _fail("order_member")
        positions[node] = position
    if len(ids) != len(request.nodes) or any(positions[a] >= positions[b] for a, b in request.edges):
        _fail("order_invalid")
    return ids


# --- the mapper request and the mapped workflow ---

def _tool(t):
    return _array([_uint(t.tool_class), _uint(t.action), _uint(t.role), _uint(t.effects), _text(t.name),
                   _text(t.description)])


def _slot(s):
    return _array([_bytes(s.ref), _uint(s.kind), _array([_uint(s.cardinality)]), _array([_uint(s.confidentiality)])])


def _relation(r):
    return _array([_uint(r.relation), _bytes(r.left), _bytes(r.right)])


def _limits(limits):
    return _array([_uint(limits.steps), _uint(limits.dependencies), _uint(limits.arguments), _uint(limits.plan_bytes)])


def validate_limits(limits):
    """PlannerLimitsV2::new."""
    if (not 0 < limits.steps <= MAX_PLAN_ITEMS or not 0 < limits.dependencies <= 0xFFFF
            or not 0 < limits.arguments <= 0xFFFF or not 0 < limits.plan_bytes <= MAX_PLAN_BYTES):
        _fail("limits")
    return limits


def mapper_request(*, template, intent, actions, slots, relations, limits, active, tools):
    """MapperIntentRequestV2::new from the envelope's fields, the active
    (class, action) pairs and the projected catalog: only active, allowed tools,
    sorted by (class, action), no duplicate."""
    allowed = set(actions)
    available = sorted((t for t in tools if (t.tool_class, t.action) in set(active) and t.action in allowed),
                       key=lambda t: (t.tool_class, t.action))
    if any((a.tool_class, a.action) == (b.tool_class, b.action) for a, b in zip(available, available[1:])):
        _fail("catalog_duplicate")
    return validate_mapper_request(MapperRequest(template, intent, tuple(actions), tuple(slots), tuple(relations),
                                                 validate_limits(Limits(*limits)), tuple(available)))


def validate_mapper_request(request):
    if not 0 < request.template <= 0xFFFFFFFF or request.intent not in INTENTS.values():
        _fail("mapper_request")
    if (len(request.actions) > MAX_NODES or any(not 0 < a <= 0xFFFFFFFF for a in request.actions)
            or any(a >= b for a, b in zip(request.actions, request.actions[1:]))):
        _fail("mapper_actions")
    slot_wires = [_slot(s) for s in request.slots]
    if (len(request.slots) > MAX_NODES or any(len(s.ref) != 16 or s.ref == bytes(16) or not 0 < s.kind <= 0xFFFFFFFF
                                             or s.cardinality not in CARDINALITIES.values()
                                             or s.confidentiality not in CONFIDENTIALITIES.values()
                                             for s in request.slots)
            or any(a >= b for a, b in zip(slot_wires, slot_wires[1:]))
            or any(a.ref >= b.ref for a, b in zip(request.slots, request.slots[1:]))):
        _fail("mapper_slots")
    relation_wires = [_relation(r) for r in request.relations]
    if (len(request.relations) > MAX_RELATIONS
            or any(not 0 < r.relation <= 0xFFFFFFFF or len(r.left) != 16 or len(r.right) != 16
                   or bytes(16) in (r.left, r.right) for r in request.relations)
            or any(a >= b for a, b in zip(relation_wires, relation_wires[1:]))):
        _fail("mapper_relations")
    validate_limits(request.limits)
    if len(request.tools) > MAX_TOOLS:
        _fail("mapper_tools")
    for previous, tool in zip((None, *request.tools), request.tools):
        if not 0 < tool.tool_class <= 0xFFFFFFFF or not 0 < tool.action <= 0xFFFFFFFF:
            _fail("mapper_tools")
        _role_effects(tool.role, tool.effects)
        semantic_text(tool.name)
        semantic_text(tool.description)
        if previous is not None and (previous.tool_class, previous.action) >= (tool.tool_class, tool.action):
            _fail("mapper_tools")
    return request


def encode_mapper_request(request):
    return _array([_uint(VERSION), _uint(request.template), _uint(request.intent),
                   _array(_uint(a) for a in request.actions), _array(_slot(s) for s in request.slots),
                   _array(_relation(r) for r in request.relations), _limits(request.limits),
                   _array(_tool(t) for t in request.tools)])


def decode_mapper_request(data):
    reader = _body(data)
    _version(reader, 8)
    template, intent = reader.uint(0xFFFFFFFF), reader.uint(0xFFFF)
    actions = tuple(reader.uint(0xFFFFFFFF) for _ in range(reader.array(MAX_NODES)))
    slots = []
    for _ in range(reader.array(MAX_NODES)):
        reader.exact_array(4)
        ref, kind = reader.bytes(16), reader.uint(0xFFFFFFFF)
        reader.exact_array(1)
        cardinality = reader.uint(0xFFFF)
        reader.exact_array(1)
        slots.append(Slot(ref, kind, cardinality, reader.uint(0xFFFF)))
    relations = []
    for _ in range(reader.array(MAX_RELATIONS)):
        reader.exact_array(3)
        relations.append(Relation(reader.uint(0xFFFFFFFF), reader.bytes(16), reader.bytes(16)))
    reader.exact_array(4)
    limits = Limits(reader.uint(0xFFFF), reader.uint(0xFFFF), reader.uint(0xFFFF), reader.uint(0xFFFFFFFF))
    tools = []
    for _ in range(reader.array(MAX_TOOLS)):
        reader.exact_array(6)
        tools.append(CatalogTool(reader.uint(0xFFFFFFFF), reader.uint(0xFFFFFFFF), reader.uint(0xFFFF),
                                 reader.uint(0xFFFF), reader.text(MAX_SEMANTIC_BYTES),
                                 reader.text(MAX_SEMANTIC_BYTES)))
    reader.end()
    request = validate_mapper_request(MapperRequest(template, intent, actions, tuple(slots), tuple(relations), limits,
                                                    tuple(tools)))
    if encode_mapper_request(request) != data:
        _fail("non_canonical")
    return request


def validate_workflow(request, workflow):
    """MappedWorkflowV2::new against its request (nodes and edges already in
    canonical order): allowed, available tools with their catalog role and
    effects, only the request's slots, the step, argument and dependency
    limits, known endpoints, no duplicate edge, acyclic."""
    limits = request.limits
    nodes, edges = workflow.nodes, workflow.edges
    if not 0 < len(nodes) <= min(MAX_NODES, limits.steps) or len(edges) > MAX_EDGES:
        _fail("workflow_size")
    if (list(nodes) != sorted(nodes, key=lambda n: n.ordinal) or list(edges) != sorted(edges)):
        _fail("workflow_order")
    available = {(t.tool_class, t.action, t.role, t.effects) for t in request.tools}
    slots, allowed = {s.ref for s in request.slots}, set(request.actions)
    index = {}
    for position, node in enumerate(nodes):
        names = [name for name, _ref in node.bindings]
        if (not 0 < node.ordinal <= 0xFFFF or node.ordinal in index or node.action not in allowed
                or (node.tool_class, node.action, node.role, node.effects) not in available
                or len(node.bindings) > min(MAX_NODES, limits.arguments)
                or any(a >= b for a, b in zip(names, names[1:]))
                or any(ref not in slots for _name, ref in node.bindings)):
            _fail("workflow_node")
        for name, ref in node.bindings:
            _argument_name(name)
            if len(ref) != 16 or ref == bytes(16):
                _fail("workflow_node")
        _role_effects(node.role, node.effects)
        index[node.ordinal] = position
    incoming, outgoing, seen = [0] * len(nodes), [0] * len(nodes), set()
    for a, b in edges:
        if a not in index or b not in index or a == b or (a, b) in seen:
            _fail("workflow_edge")
        seen.add((a, b))
        outgoing[index[a]] += 1
        incoming[index[b]] += 1
    if (any(v > min(255, limits.dependencies) for v in incoming) or any(v > 255 for v in outgoing)
            or not _acyclic(len(nodes), [(index[a], index[b]) for a, b in edges])):
        _fail("workflow_limits")
    return workflow


def encode_workflow(workflow):
    return _array([_uint(VERSION),
                   _array(_array([_uint(n.ordinal), _uint(n.tool_class), _uint(n.action),
                                  _array(_array([_text(name), _bytes(ref)]) for name, ref in n.bindings),
                                  _uint(n.role), _uint(n.effects)]) for n in workflow.nodes),
                   _array(_array([_uint(a), _uint(b)]) for a, b in workflow.edges)])


def decode_workflow(data, request):
    reader = _body(data)
    _version(reader, 3)
    count = reader.array(min(MAX_NODES, request.limits.steps))
    if not count:
        _fail("workflow_size")
    nodes = []
    for _ in range(count):
        reader.exact_array(6)
        ordinal, tool_class, action = reader.uint(0xFFFF), reader.uint(0xFFFFFFFF), reader.uint(0xFFFFFFFF)
        bindings = []
        for _ in range(reader.array(min(MAX_NODES, request.limits.arguments))):
            reader.exact_array(2)
            bindings.append((_argument_name(reader.text(MAX_ARGUMENT_NAME_BYTES * 4)), reader.bytes(16)))
        nodes.append(MappedNode(ordinal, tool_class, action, tuple(bindings), reader.uint(0xFFFF),
                                reader.uint(0xFFFF)))
    edges = []
    for _ in range(reader.array(MAX_EDGES)):
        reader.exact_array(2)
        edges.append((reader.uint(0xFFFF), reader.uint(0xFFFF)))
    reader.end()
    workflow = Workflow(tuple(sorted(nodes, key=lambda n: n.ordinal)), tuple(sorted(edges)))
    validate_workflow(request, workflow)
    if encode_workflow(workflow) != data:
        _fail("non_canonical")
    return workflow


# --- the decoded plan agentd commits (savana-kernel-protocol PlannerPlanV2) ---

def validate_plan(plan):
    """PlannerStepV2::new and PlannerPlanV2::new."""
    if len(plan.nonce) != 32 or plan.nonce == bytes(32) or len(plan.steps) > MAX_PLAN_ITEMS:
        _fail("plan_shape")
    for position, step in enumerate(plan.steps, 1):
        names = [name for name, _ref in step.bindings]
        if (step.ordinal != position or not 0 < step.action <= 0xFFFFFFFF or not 0 < step.tool_class <= 0xFFFFFFFF
                or len(step.bindings) > MAX_PLAN_ITEMS or len(step.dependencies) > MAX_PLAN_ITEMS
                or any(len(ref) != 16 or ref == bytes(16) for _name, ref in step.bindings)
                or any(a >= b for a, b in zip(names, names[1:]))
                or any(a >= b for a, b in zip(step.dependencies, step.dependencies[1:]))
                or any(not 0 < d < step.ordinal for d in step.dependencies)):
            _fail("plan_step")
        for name in names:
            _argument_name(name)
    return plan


def encode_plan(plan):
    return _array([_uint(VERSION), _bytes(plan.nonce),
                   _array(_array([_uint(s.ordinal), _uint(s.action), _uint(s.tool_class),
                                  _array(_array([_text(name), _bytes(ref)]) for name, ref in s.bindings),
                                  _array(_uint(d) for d in s.dependencies)]) for s in plan.steps)])


def decode_plan(data):
    reader = _body(data)
    _version(reader, 3)
    nonce, steps = reader.bytes(32), []
    for _ in range(reader.array(MAX_PLAN_ITEMS)):
        reader.exact_array(5)
        ordinal, action, tool_class = reader.uint(0xFFFF), reader.uint(0xFFFFFFFF), reader.uint(0xFFFFFFFF)
        bindings = []
        for _ in range(reader.array(MAX_PLAN_ITEMS)):
            reader.exact_array(2)
            bindings.append((reader.text(MAX_ARGUMENT_NAME_BYTES * 4), reader.bytes(16)))
        dependencies = tuple(reader.uint(0xFFFF) for _ in range(reader.array(MAX_PLAN_ITEMS)))
        steps.append(PlanStep(ordinal, action, tool_class, tuple(bindings), dependencies))
    reader.end()
    plan = validate_plan(PlannerPlan(nonce, tuple(steps)))
    if encode_plan(plan) != data:
        _fail("non_canonical")
    return plan


def decode_order(table_nodes, table_edges, ids, positions_of):
    """decode_ordered_plan_v2 for a caller that knows which mapped node each
    planner id stands for (`positions_of`: id -> mapped ordinal): each step
    is that node's tool and bindings, its dependencies the plan positions of
    its in-edges. Used by tests and the offline verifier."""
    nodes = {n.ordinal: n for n in table_nodes}
    order = [positions_of[i] for i in ids]
    if sorted(order) != sorted(nodes):
        _fail("order_member")
    position = {ordinal: p for p, ordinal in enumerate(order, 1)}
    steps = []
    for p, ordinal in enumerate(order, 1):
        deps = sorted(position[a] for a, b in table_edges if b == ordinal)
        if any(d >= p for d in deps):
            _fail("order_invalid")
        node = nodes[ordinal]
        steps.append(PlanStep(p, node.action, node.tool_class, node.bindings, tuple(deps)))
    return tuple(steps)


# --- one request per connection over pinned mutual TLS ---

def response_bytes(body):
    """The only response agentd's validate_response_header accepts."""
    return (f"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {len(body)}\r\n"
            "Connection: close\r\n\r\n").encode("ascii") + body


def request_header(path, authority, size):
    """Exactly the header agentd's PinnedMtlsCborEndpointV2 writes."""
    return (f"POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/cbor\r\n"
            f"Accept: application/cbor\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n").encode("ascii")


class OneShotServer:
    """A stand-in model endpoint: sequential connections, each one mutual-TLS
    handshake (TLS 1.3, ALPN http/1.1, the pinned client certificate), one
    request in agentd's exact header form, one handler call, one response and
    TLS close_notify. A handler error closes the connection without a reply,
    which agentd reports as an unavailable endpoint; nothing is retried and no
    exception text is kept."""

    def __init__(self, *, context, client_pin, host, path, handler, address=("127.0.0.1", 0), timeout=40.0):
        if type(client_pin) is not bytes or len(client_pin) != 32 or not callable(handler):
            raise ValueError("server_binding")
        self.context, self.client_pin, self.path, self.handler = context, client_pin, path, handler
        self.timeout = timeout
        self.host = host
        self.connections = self.served = self.rejected = 0
        self._stop = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listener.bind(address)
            self.listener.listen(8)
            self.listener.settimeout(.2)
        except BaseException:
            self.listener.close()
            raise
        self.address = self.listener.getsockname()
        self.authority = host if self.address[1] == 443 else f"{host}:{self.address[1]}"
        self._thread = threading.Thread(target=self._serve, name="savana-structured-" + path.strip("/"), daemon=True)

    def start(self):
        self._thread.start()
        return self

    def _serve(self):
        while not self._stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections += 1
            try:
                self._connection(raw)
                self.served += 1
            except Exception:
                self.rejected += 1
            finally:
                raw.close()

    def _connection(self, raw):
        end = time.monotonic() + self.timeout

        def remaining():
            left = end - time.monotonic()
            if left <= 0:
                raise TimeoutError("endpoint_deadline")
            return left
        raw.settimeout(min(remaining(), 10))
        with self.context.wrap_socket(raw, server_side=True) as tls:
            if (tls.selected_alpn_protocol() != "http/1.1"
                    or hashlib.sha256(tls.getpeercert(binary_form=True)).digest() != self.client_pin):
                raise ValueError("client_binding")

            def read(size):
                parts = bytearray()
                while len(parts) < size:
                    tls.settimeout(min(remaining(), 10))
                    part = tls.recv(size - len(parts))
                    if not part:
                        raise EOFError("request_truncated")
                    parts.extend(part)
                return bytes(parts)
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                if len(header) >= 4096:
                    raise ValueError("header_bound")
                header.extend(read(1))
            # The whole header must be byte for byte the one agentd writes.
            lengths = [line[16:] for line in bytes(header).split(b"\r\n") if line.startswith(b"Content-Length: ")]
            size = int(lengths[0]) if len(lengths) == 1 and re.fullmatch(rb"[1-9][0-9]{0,8}", lengths[0]) else 0
            if not 0 < size <= MAX_BODY or bytes(header) != request_header(self.path, self.authority, size):
                raise ValueError("request_header")
            body = read(size)
            reply = self.handler(body)
            if type(reply) is not bytes or not 0 < len(reply) <= MAX_BODY:
                raise ValueError("handler_reply")
            tls.settimeout(min(remaining(), 10))
            tls.sendall(response_bytes(reply))
            # agentd reads to a clean EOF: it needs TLS close_notify.
            try:
                tls.settimeout(min(remaining(), 5))
                tls.unwrap().close()
            except (OSError, ssl.SSLError, TimeoutError):
                pass

    def settled(self, timeout=5.0):
        """Whether every accepted connection has been handled (a client may
        see the reply before this thread finishes the close)."""
        end = time.monotonic() + timeout
        while self.served + self.rejected < self.connections and time.monotonic() < end:
            time.sleep(.01)
        return self.served + self.rejected == self.connections

    def close(self):
        self._stop.set()
        self.listener.close()
        if self._thread.ident is not None:
            self._thread.join(self.timeout + 5)
            if self._thread.is_alive():
                raise RuntimeError("endpoint_shutdown_uncertain")


# --- a per-run certificate authority ---

class EphemeralPki:
    """One run's CA (ECDSA P-256), one server certificate per endpoint host and
    one client certificate, in the profile of agentd's TLS test fixtures.
    Nothing is written to disk: Python's TLS loads each server key through an
    anonymous memory file, and the client key exists only as bytes this
    process hands to the agentd example over its stdin."""

    def __init__(self, hosts, *, client_name="savana-structured-eval", days=1):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
        import datetime
        now = datetime.datetime.now(datetime.timezone.utc)
        der, pem = serialization.Encoding.DER, serialization.Encoding.PEM
        pkcs8, spki = serialization.PrivateFormat.PKCS8, serialization.PublicFormat.SubjectPublicKeyInfo

        def name(text):
            return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])

        def usage(sign, **flags):
            return x509.KeyUsage(digital_signature=sign, content_commitment=False, key_encipherment=False,
                                 data_encipherment=False, key_agreement=False, encipher_only=False,
                                 decipher_only=False, **flags)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca = (x509.CertificateBuilder().subject_name(name("Savana Structured Eval CA"))
              .issuer_name(name("Savana Structured Eval CA")).public_key(ca_key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
              .not_valid_after(now + datetime.timedelta(days=days))
              .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
              .add_extension(usage(False, key_cert_sign=True, crl_sign=True), critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
              .sign(ca_key, hashes.SHA256()))

        def leaf(subject, purpose, san=None):
            key = ec.generate_private_key(ec.SECP256R1())
            builder = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(ca.subject)
                       .public_key(key.public_key()).serial_number(x509.random_serial_number())
                       .not_valid_before(now - datetime.timedelta(minutes=5))
                       .not_valid_after(now + datetime.timedelta(days=days))
                       .add_extension(x509.ExtendedKeyUsage([purpose]), critical=False)
                       .add_extension(usage(True, key_cert_sign=False, crl_sign=False), critical=True)
                       .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                       .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                                      critical=False))
            if san:
                builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False)
            return key, builder.sign(ca_key, hashes.SHA256())
        self.ca_der = ca.public_bytes(der)
        self._ca_pem = ca.public_bytes(pem).decode("ascii")
        client_key, client = leaf(client_name, ExtendedKeyUsageOID.CLIENT_AUTH)
        self.client_der = client.public_bytes(der)
        self.client_key_der = client_key.private_bytes(der, pkcs8, serialization.NoEncryption())
        self.client_pin = hashlib.sha256(self.client_der).digest()
        self.server_pins, self._contexts = {}, {}
        for host in hosts:
            key, certificate = leaf(host, ExtendedKeyUsageOID.SERVER_AUTH, san=host)
            self.server_pins[host] = hashlib.sha256(certificate.public_key().public_bytes(der, spki)).digest()
            self._contexts[host] = self._context(certificate.public_bytes(pem)
                                                 + key.private_bytes(pem, pkcs8, serialization.NoEncryption()))

    def _context(self, chain):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cadata=self._ca_pem)
        context.set_alpn_protocols(["http/1.1"])
        context.num_tickets = 0
        fd = os.memfd_create("savana-structured-endpoint", os.MFD_CLOEXEC)
        try:
            os.write(fd, chain)
            context.load_cert_chain(f"/proc/self/fd/{fd}")
        finally:
            os.close(fd)
        return context

    def server_context(self, host):
        return self._contexts[host]


# --- the agentd example driver as a child process ---

EXAMPLE_SCHEMA = "savana-structured-plan-eval-v1"
MAX_LINE = 16 * 1024 * 1024


class ExampleProcess:
    """`structured_plan_eval` over JSON lines: started with an empty
    environment, configured once from memory (its client key goes through the
    pipe, never argv, a file or a log), then one reply line per job line. Its
    stderr is discarded: it writes fixed codes only, on stdout."""

    def __init__(self, executable, config, *, timeout=30.0):
        self._process = subprocess.Popen([str(executable)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, env={}, cwd="/", close_fds=True)
        self._buffer = bytearray()
        try:
            self._send(dict(config, schema=EXAMPLE_SCHEMA))
            if self._receive(timeout) != {"ready": True}:
                raise RuntimeError("example_not_ready")
        except BaseException:
            self.close()
            raise

    def _send(self, value):
        self._process.stdin.write(json.dumps(value, separators=(",", ":")).encode() + b"\n")
        self._process.stdin.flush()

    def _receive(self, timeout):
        deadline = time.monotonic() + timeout
        fd = self._process.stdout.fileno()
        while b"\n" not in self._buffer:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([fd], [], [], left)[0]:
                raise TimeoutError("example_reply_timeout")
            chunk = os.read(fd, 65536)
            if not chunk:
                raise RuntimeError("example_exited")
            self._buffer.extend(chunk)
            if len(self._buffer) > MAX_LINE:
                raise RuntimeError("example_reply_size")
        line, _, rest = bytes(self._buffer).partition(b"\n")
        self._buffer = bytearray(rest)
        return json.loads(line)

    @property
    def pid(self):
        return self._process.pid

    def request(self, value, *, timeout=90.0):
        self._send(value)
        return self._receive(timeout)

    def close(self):
        process = self._process
        try:
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            process.wait(5)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
            process.wait(5)
        finally:
            if process.stdout:
                process.stdout.close()
