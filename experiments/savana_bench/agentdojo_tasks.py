"""Reviewed finite AgentDojo task authoring, NOT a root signer or score runner.

The reviewed tool catalog, the operations and result edges of a contract, and
the owner document and unsigned finite draft of a planner-drafted contract the
owner's review admitted (`drafted_tasks`). No task objects, reference
solutions, environments, attack labels or model output are accepted. The
output must pass native compilation against an independently signed root and
tool registry before it can run.
"""
from dataclasses import dataclass
import functools
import hashlib
import json

from .agentdojo_provider import canonical

BENCHMARK = "v1.2.2"
SUITE = "workspace"
PACKAGE_VERSION = "0.1.35"
# Operator policy, not a fact extracted from a result or an oracle. The public
# benchmark calendar is dated 2024-05-15. Prompts omitting a year use this year.
CALENDAR_YEAR = 2024


@dataclass(frozen=True)
class Step:
    """One reviewed operation of a contract, in execution order.

    `values` are the owner-committed texts for this operation's fields (the
    synthetic body/calendar/to sentinels included). `derived` names each field
    the kernel fills from an EARLIER operation's verified result, as
    (field, source_operation, json_path, max_bytes): the owner signs that edge,
    never a value, and neither the planner nor this module chooses it.
    `payload_from` names the earlier operation whose WHOLE verified result the
    kernel passes as this operation's payload (0 = the payload is an owner
    value). A payload is not a root control: its source is fixed by this
    reviewed contract and checked again when the owner approves the action.

    A derived edge may carry a fifth element, its form: LIST (the node is an
    array of texts, for a text-list field) or (op, amount) (one text the kernel
    computes with an owner-signed operation, `COMPUTE_OPS`). A list field's
    owner value is a tuple of texts. An uncomputed edge may carry a sixth, the
    candidate set the owner signs for it (a trusted-set origin, `edge_candidates`).
    """
    tool: str
    upstream_tool: str
    values: tuple[tuple[str, object], ...]
    derived: tuple[tuple, ...] = ()
    payload_from: int = 0

    def value_map(self):
        return {k: list(v) if type(v) is tuple else v for k, v in self.values}

    def edges(self):
        """Every derived edge as (field, source, path, bound, form)."""
        return tuple(edge_parts(e) for e in self.derived)


LIST = "list"
# Owner-signed computations on one extracted text, mirrored exactly from the
# kernel (savana-continuation-core planning_observation::ResultComputeV04).
COMPUTE_OPS = {"add_minutes": (1, 527_040), "add_days": (2, 3_660), "add_cents": (3, 1_000_000_000)}
MAX_LIST_ITEMS = 32


MAX_CANDIDATES = 64
MAX_CANDIDATE_BYTES = 4096


def edge_parts(edge):
    field, source, path, bound, *rest = edge
    form = rest[0] if rest else None
    if not (form is None or form == LIST or (type(form) is tuple and len(form) == 2 and form[0] in COMPUTE_OPS
                                             and type(form[1]) is int
                                             and abs(form[1]) <= COMPUTE_OPS[form[0]][1])) or len(rest) > 2:
        raise ValueError("edge_form")
    if len(rest) == 2:
        edge_candidates(edge)
    return field, source, tuple(path), bound, form


def edge_candidates(edge):
    """The candidate set an edge carries (members strictly ascending by bytes,
    each a trimmed text within the edge's bound), or None. Only an uncomputed
    text or list edge carries one; the kernel endorses a derived value only if
    it is, byte for byte, a member (for a list, every item)."""
    if len(edge) < 6:
        return None
    members, form, bound = edge[5], edge[4], edge[3]
    encoded = [m.encode() for m in members] if type(members) is tuple and all(type(m) is str for m in members) else None
    if (form not in (None, LIST) or encoded is None or not 1 <= len(encoded) <= MAX_CANDIDATES
            or sum(map(len, encoded)) > MAX_CANDIDATE_BYTES or encoded != sorted(set(encoded))
            or any(not m or m.strip() != m or len(m.encode()) > bound or any(ord(c) < 32 for c in m)
                   for m in members)):
        raise ValueError("edge_candidates")
    return members


def edge_document(edge):
    """An edge as contract evidence; a plain edge keeps its historical shape."""
    field, source, path, bound, form = edge_parts(edge)
    doc = {"field": field, "source_operation": source, "path": list(path), "max_bytes": bound}
    if form == LIST:
        doc["list"] = True
    elif form is not None:
        doc["compute"] = {"op": form[0], "amount": form[1]}
    if edge_candidates(edge) is not None:
        doc["candidates"] = list(edge_candidates(edge))
    return doc


def _days(y, m, d):
    import datetime
    if not 1000 <= y <= 9999:
        raise ValueError("compute_operand")
    return (datetime.date(y, m, d) - datetime.date(1970, 1, 1)).days


def _date(days):
    import datetime
    value = datetime.date(1970, 1, 1) + datetime.timedelta(days=days)
    if not 1000 <= value.year <= 9999:
        raise ValueError("compute_range")
    return value.isoformat()


def _fixed_digits(text, width):
    if len(text) != width or not text.isascii() or not text.isdigit():
        raise ValueError("compute_operand")
    return int(text)


def _parse_date(text):
    parts = text.split("-")
    if len(parts) != 3:
        raise ValueError("compute_operand")
    return _days(_fixed_digits(parts[0], 4), _fixed_digits(parts[1], 2), _fixed_digits(parts[2], 2))


def _parse_time(text):
    parts = text.split(":")
    if len(parts) != 2:
        raise ValueError("compute_operand")
    hour, minute = _fixed_digits(parts[0], 2), _fixed_digits(parts[1], 2)
    if hour > 23 or minute > 59:
        raise ValueError("compute_operand")
    return hour * 60 + minute


def apply_compute(form, text):
    """The kernel's computation on one extracted text, or ValueError."""
    op, amount = form
    if op not in COMPUTE_OPS or type(amount) is not int or abs(amount) > COMPUTE_OPS[op][1] or type(text) is not str:
        raise ValueError("compute_form")
    if op == "add_minutes":
        date, sep, time = text.partition(" ")
        if not sep:
            raise ValueError("compute_operand")
        total = _parse_date(date) * 1440 + _parse_time(time) + amount
        day, minute = divmod(total, 1440)
        return f"{_date(day)} {minute // 60:02d}:{minute % 60:02d}"
    if op == "add_days":
        date, sep, time = text.partition(" ")
        if sep:
            _parse_time(time)
        return _date(_parse_date(date) + amount) + (f" {time}" if sep else "")
    whole, dot, fraction = text.partition(".")
    if (not whole or len(whole) > 12 or not whole.isascii() or not whole.isdigit()
            or (len(whole) > 1 and whole.startswith("0")) or (dot and not 1 <= len(fraction) <= 2)
            or (dot and not (fraction.isascii() and fraction.isdigit()))):
        raise ValueError("compute_operand")
    cents = int(whole) * 100 + (int(fraction.ljust(2, "0")) if dot else 0) + amount
    if cents < 0:
        raise ValueError("compute_range")
    return f"{cents // 100}.{cents % 100:02d}"


# Deployment-shipped read tools, in registry order (tool_class/action_template
# are 202+i / 102+i). Each maps a reviewed dojo operation to one official
# AgentDojo read function and its non-role parameters. body/calendar/to are the
# synthetic payload/resource/destination sentinels every business profile needs.
TOOL_CATALOG = (
    ("dojo.calendar.search", "search_calendar_events", ("date", "query")),
    ("dojo.calendar.day", "get_day_calendar_events", ("day",)),
    ("dojo.email.search", "search_emails", ("query",)),
    ("dojo.email.unread", "get_unread_emails", ()),
    ("dojo.file.list", "list_files", ()),
    ("dojo.file.search_name", "search_files_by_filename", ("filename",)),
    ("dojo.file.search", "search_files", ("query",)),
)

# Deployment-shipped WRITE tools. Each maps a reviewed dojo operation to one
# official AgentDojo authorizing function, the authorizing effect, and its
# business fields with EXPLICIT roles (a write tool's resource/destination carry
# real owner values, unlike a read tool's fixed calendar/to sentinels). Every
# write tool MUST carry the intent_flow_confinement validator, so a call binding
# an untrusted-derived argument escalates to owner approval at G5 instead of
# executing silently. Scalar only for now (no arrays, no computed values).
WRITE_VALIDATORS = ("intent_flow_confinement",)
WRITE_CATALOG = (
    # append_to_file(file_id, content): file_id is the owner-fixed resource;
    # content is a (result-derived) parameter; body/to are synthetic
    # payload/destination sentinels a business profile always needs.
    ("dojo.file.append", "append_to_file", "update",
     (("body", "payload"), ("content", "parameter"),
      ("file_id", "resource"), ("to", "destination"))),
)


# Deployment-shipped MODEL tools: a quarantined generator the kernel treats as
# one more external tool. Its whole input is an earlier result passed as the
# payload (data, never instructions), its instruction is the owner's own text,
# and its output is untrusted data that can reach a later field only through an
# owner-signed result edge. It sends private data to a model provider, so it is
# declared as a SEND effect with intent-flow confinement: every call is an
# owner-approved action, never a silent step.
GENERATOR_MODEL = "deepseek-flash"
MODEL_CATALOG = (
    # Planner-drafted programs (G3): the same quarantined model, asked for the
    # one value a named target field (or the owner's final answer) needs. The
    # target is an inert catalog label; the instruction is the owner's text;
    # the optional context is an earlier extraction's value (a signed edge), so
    # one answer can combine several results (up to five contexts). `question` is
    # owner text: the condition a "condition" target answers yes or no (else
    # empty). `source` names the step whose
    # result is the payload, so two extractions are never the same signed
    # alternative (the kernel refuses an ambiguous match).
    ("dojo.model.extract", "quarantined_extract", "send",
     (("body", "payload"), ("context", "parameter"), ("context2", "parameter"), ("context3", "parameter"),
      ("context4", "parameter"), ("context5", "parameter"), ("instruction", "parameter"), ("model", "resource"),
      ("question", "parameter"), ("source", "parameter"), ("target", "parameter"), ("to", "destination"))),
)


# Deterministic computation over earlier results (`dojo_compute`): a READ that
# contacts nothing and changes nothing. Its inputs are owner-signed result
# edges, its filter/order/output texts are owner-declared constants, and its
# output is data that reaches a later field only through a signed edge.
def _compute_catalog():
    from .dojo_compute import COMPUTE_TOOL, COMPUTE_UPSTREAM, FIELDS
    return ((COMPUTE_TOOL, COMPUTE_UPSTREAM, "read",
             (("body", "payload"), ("calendar", "resource"), ("to", "destination"),
              *((name, "parameter") for name in FIELDS))),)


def upstream_for(tool):
    for name, upstream, *_ in (*TOOL_CATALOG, *WRITE_CATALOG, *MODEL_CATALOG, *_compute_catalog()):
        if name == tool:
            return upstream
    from .dojo_catalog import entry
    return entry(tool)["upstream"]


# How a deployment ships the model tools: "mcp" (their provider receives the
# arguments, as any connector's does) or "mcp_model" (the kernel's executor
# masks every argument with the leak gate's table before the request leaves
# the host and unmasks the reply; the `masked` extractor view).
MODEL_CODECS = ("mcp", "mcp_model")
MODEL_OPERATIONS = frozenset(name for name, *_ in MODEL_CATALOG)


def catalog_json(suite=SUITE, model_codec=MODEL_CODECS[0]):
    """Reviewed tool catalog of one suite for the deployment generator: every
    AgentDojo tool of that suite (`dojo_catalog`; for workspace the original
    tools first and unchanged), the quarantined extractor (`model_codec`) and
    the compute step, which the executor evaluates itself (codec
    "table_compute"). Every synthetic control carries its deployment-fixed
    value; authorizing tools carry explicit roles and the
    intent-flow-confinement validator."""
    from .dojo_catalog import SENTINELS, catalog_document
    if model_codec not in MODEL_CODECS:
        raise ValueError("model_codec")

    def fields(spec, fixed):
        return [dict({"name": n, "role": r, "type": "text"}, **({"fixed": SENTINELS[n]} if n in fixed else {}))
                for n, r in sorted(spec)]
    model_tools = [dict({"operation": name, "effect": effect, "fixed_magnitude": 1,
                         "fields": fields(spec, {"to"}), "validators": list(WRITE_VALIDATORS)},
                        **({} if model_codec == "mcp" else {"codec": model_codec}))
                   for name, _, effect, spec in MODEL_CATALOG]
    compute_tools = [{"operation": name, "effect": effect, "fixed_magnitude": 1, "codec": "table_compute",
                      "fields": fields(spec, {"body", "calendar", "to"})}
                     for name, _, effect, spec in _compute_catalog()]
    return catalog_document(suite, extra_write_tools=model_tools, extra_read_tools=compute_tools)


def catalog_operations(suite=SUITE):
    """Every operation a deployment of `suite` ships a signed descriptor for."""
    doc = catalog_json(suite)
    return {t["operation"] for t in (*doc["read_tools"], *doc["write_tools"])}


EFFECT_CODES = {"read": 1, "create": 2, "update": 3, "delete": 4, "send": 5, "execute": 6}
EFFECT_NAMES = {"read": "Read", "create": "Create", "update": "Update", "delete": "Delete",
                "send": "Send", "execute": "Execute"}
ROLE_CODES = {"resource": 1, "destination": 2, "magnitude": 3, "payload": 4, "parameter": 5, "condition": 6,
              "copy_destination": 7}
TYPE_CODES = {"text": 1, "text_list": 4}


def signed_edge(edge):
    """One derived edge in the clause-draft form the owner signs."""
    _field, source, path, bound, form = edge_parts(edge)
    rule = dict(source_clause=source, path=list(path), kind=TYPE_CODES["text_list" if form == LIST else "text"],
                max_bytes=bound)
    if form not in (None, LIST):
        rule["compute"] = dict(op=form[0], amount=form[1])
    if edge_candidates(edge) is not None:
        rule["candidates"] = list(edge_candidates(edge))
    return rule


@functools.lru_cache(maxsize=None)
def _catalog_index(model_codec):
    from .dojo_catalog import SUITES
    index = {}
    for suite in SUITES:
        doc = catalog_json(suite, model_codec)
        for entry in (*doc["read_tools"], *doc["write_tools"]):
            index.setdefault(entry["operation"], canonical(entry))
    return index


def catalog_tool(tool, model_codec=MODEL_CODECS[0]):
    """The reviewed catalog entry (operation, effect, fields, codec) for one
    tool, as a deployment shipping the model tools with `model_codec` has it."""
    entry = _catalog_index(model_codec).get(tool)
    if entry is None:
        raise ValueError("unreviewed_tool")
    return json.loads(entry)


def select_result_path(response_bytes, path, *, node_only=False):
    """Python mirror of the kernel's strict result-path projection, used only by
    the researcher endpoint to CHECK the value the kernel derived. `$json` on a
    string decodes nested JSON text; on an object it is an ordinary key."""
    def unique(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError("duplicate_key")
            out[k] = v
        return out
    node = json.loads(response_bytes, object_pairs_hook=unique)
    for key in path:
        if key == "$json" and isinstance(node, str):
            node = json.loads(node, object_pairs_hook=unique)
        elif isinstance(node, dict):
            node = node[key]
        elif isinstance(node, list) and key.isdigit() and str(int(key)) == key:
            node = node[int(key)]
        else:
            raise ValueError("path_miss")
    if node_only:
        return node
    if not isinstance(node, (str, bool, int)) or isinstance(node, float):
        raise ValueError("non_scalar")
    return node


def select_result_list(response_bytes, path, max_bytes):
    """Mirror of the kernel's text-list projection: an array of at most
    MAX_LIST_ITEMS strings whose total UTF-8 length is within `max_bytes`."""
    node = select_result_path(response_bytes, path, node_only=True)
    if (type(node) is not list or len(node) > MAX_LIST_ITEMS or any(type(i) is not str for i in node)
            or sum(len(i.encode()) for i in node) > max_bytes):
        raise ValueError("non_list")
    return node


def edge_value(prior_results, edge):
    """The value the kernel derives for one edge from the actual earlier
    result bytes, or ValueError (the kernel refuses the step)."""
    _field, source, path, bound, form = edge_parts(edge)
    raw = prior_results[source - 1]
    if form == LIST:
        return select_result_list(raw, path, bound)
    value = select_result_path(raw, path)
    if form is not None:
        value = apply_compute(form, value) if type(value) is str else None
    if type(value) is not str or len(value.encode()) > bound:
        raise ValueError("derived_value_out_of_bounds")
    return value


# The generator's one line of output (its result is the JSON object {"text": ...}).
GENERATED_TEXT = ("result", "content", "0", "text", "$json", "text")
# For a text-list target the extractor's result also carries its items.
GENERATED_ITEMS = ("result", "content", "0", "text", "$json", "items")
GENERATED_MAX_BYTES = 512


# Planner-drafted contracts the owner side reviewed in this process (G3).
_DRAFTED = {}


def register_drafted(contract):
    """Admit an owner-reviewed DraftedContract to this process's catalog."""
    from .drafted_tasks import DraftedContract
    if type(contract) is not DraftedContract:
        raise ValueError("drafted_contract_required")
    _DRAFTED[contract.contract_id] = contract
    return contract


def all_contracts():
    """Every contract this process may author: the owner-reviewed drafted ones."""
    return tuple(_DRAFTED.values())


def expected_step_call(contract, number, prior_results):
    """The one authorized tools/call params for operation `number` (0-based):
    the owner's committed values plus each derived field recomputed from the
    actual earlier result bytes at the signed path. Used by the researcher
    endpoint, the runner's attempt verdicts and the offline verifier alike."""
    step = contract.steps()[number]
    arguments = step.value_map()
    if step.payload_from:
        # The kernel decodes the whole earlier result as the payload text.
        payload = next(f["name"] for f in catalog_tool(step.tool)["fields"] if f["role"] == "payload")
        arguments[payload] = prior_results[step.payload_from - 1].decode("utf-8")
    for edge in step.derived:
        arguments[edge[0]] = edge_value(prior_results, edge)
    return {"name": step.tool, "arguments": arguments}


def expected_wire_params(contract, number, prior_results, model_codec=MODEL_CODECS[0]):
    """(the tools/call params operation `number` reaches its provider with,
    the Masker that puts the reply back or None): `expected_step_call`, and
    for a model tool shipped with the model codec, the kernel executor's
    masking of it (`value_blind.mask_model_call`)."""
    params = expected_step_call(contract, number, prior_results)
    if model_codec == "mcp" or params["name"] not in MODEL_OPERATIONS:
        return params, None
    from .value_blind import mask_model_call
    arguments, masker = mask_model_call(catalog_tool(params["name"], model_codec)["fields"], params["arguments"])
    return dict(params, arguments=arguments), masker


# The request id a local reply is recorded with here. The executor's own reply
# echoes the kernel's id (`step-` and a digest only the kernel knows); a review
# never lets a later operation read a local reply's envelope, only its text.
LOCAL_REQUEST_ID = "local"


def executor_local_text(contract, number, prior_results):
    """The text the kernel's executor answers operation `number` with itself,
    contacting no provider (crates/savana-execd `local_business_response`),
    or None: a guarded call whose condition does not hold answers SKIPPED; the
    compute step answers its evaluation (`dojo_compute.compute`, the
    reference the executor's evaluator is byte-exact with)."""
    from .dojo_catalog import SKIPPED, guard_holds
    from .dojo_compute import COMPUTE_TOOL, FILTER_FIELDS, INPUT_FIELDS, ORDER_FIELDS, OUTPUT_FIELD, compute
    step = contract.steps()[number]
    conditions = [f["name"] for f in catalog_tool(step.tool)["fields"] if f["role"] == "condition"]
    if not conditions and step.tool != COMPUTE_TOOL:
        return None
    arguments = expected_step_call(contract, number, prior_results)["arguments"]
    if conditions and not guard_holds(arguments[conditions[0]]):
        return SKIPPED
    if step.tool != COMPUTE_TOOL:
        return None
    output = compute([arguments[name] for name in INPUT_FIELDS], [arguments[name] for name in FILTER_FIELDS],
                     [arguments[name] for name in ORDER_FIELDS], arguments[OUTPUT_FIELD], calc=True)
    return canonical(output).decode("utf-8")


def result_slot(contract, operation, field):
    """Opaque slot naming a result edge; distinct from every owner input slot."""
    return list(hashlib.sha256(b"SAVANA_DOJO_RESULT_SLOT_V1\0" + bytes.fromhex(contract.digest())
                               + f"{operation}:{field}".encode()).digest()[:16])


def _digest(value):
    if type(value) is not bytes or len(value) != 32 or value == bytes(32):
        raise ValueError("nonzero_digest_required")
    return list(value)


def owner_inputs(contract):
    """Data slots, not capabilities. Ownership is supplied by real ingress/run.

    Independent of future task/root IDs so the full input can be consented
    before those identities are available. Rust binds every value to its run.
    The first operation's slots keep their historical names; a later
    operation's are prefixed with its id, so two operations never share a slot.
    """
    if contract not in all_contracts():
        raise ValueError("unreviewed_contract")
    steps = contract.steps()
    rows = []
    for number, step in enumerate(steps, 1):
        for name, value in step.values:
            key = name if number == 1 else f"{number}:{name}"
            row = dict(argument=name, slot=list(hashlib.sha256(
                b"SAVANA_DOJO_INPUT_SLOT_V2\0" + bytes.fromhex(contract.digest()) + key.encode()).digest()[:16]),
                text="" if type(value) is tuple else value)
            if type(value) is tuple:
                # A text-list field's owner value: typed items, never one text.
                row["items"] = list(value)
            if len(steps) > 1:
                row["operation"] = number
            rows.append(row)
    return rows


def owner_document(contract):
    """The owner's consented input document in the one schema the kernel
    accepts (schema 3): the request, every owner input by slot, and the
    owner-declared constants, each with every (operation, field) it fills.
    The kernel holds each input to request text for every field it fills (a
    whole token of it in a destination-class field), a constant bound to
    exactly that field (never a destination-class one), or the field's
    deployment-fixed value."""
    inputs = sorted([dict(slot=i["slot"], text=i["text"], **({"items": i["items"]} if "items" in i else {}))
                     for i in owner_inputs(contract)], key=lambda i: i["slot"])
    return canonical(dict(schema=3, prompt=contract.prompt, inputs=inputs, origin="owner_text",
                          constants=contract.bound_constants())).decode("utf-8")


def prepare_draft(contract, *, task, root, observer, tool_descriptor,
                  release_descriptor, application_turn, planner, model_profile,
                  not_before, expires_at, tool_clause=1, release_clause=2,
                  step_descriptors=None):
    """Prepare an unsigned v0.4 finite draft and private input slot records.

    Roots/descriptors here are references supplied by the operator. This helper
    does NOT prove they exist or authorize these values. Native live compilation,
    owned input pinning, recipe approval, G3 and FinalRelease are still required.
    The single planner choice authorizes no tool arguments; all are fixed below.
    Operation i runs under owner clause i; a result-derived field is bound as a
    result edge from its source operation at the signed path, never a value.
    """
    if contract not in all_contracts():
        raise ValueError("unreviewed_contract")
    steps = contract.steps()
    descriptors = tuple(step_descriptors) if step_descriptors is not None else (tool_descriptor,)
    ids = {k: _digest(v) for k, v in {
        "task": task, "root": root, "observer": observer,
        "release": release_descriptor, "turn": application_turn, "planner": planner,
    }.items()}
    tools = [_digest(d) for d in descriptors]
    if len(steps) > 1 and (tool_clause, release_clause) != (1, 2):
        raise ValueError("invalid_task_draft_binding")
    clauses = [tool_clause] if len(steps) == 1 else list(range(1, len(steps) + 1))
    release_clause = release_clause if len(steps) == 1 else len(steps) + 1
    if (type(model_profile) is not int or not 1 <= model_profile <= 65535
        or len(tools) != len(steps)
        or any(type(v) is not int or not 1 <= v < 2**64
               for v in (not_before, expires_at, *clauses, release_clause))
        or not not_before < expires_at or expires_at - not_before < 2
        or release_clause in clauses or release_descriptor in descriptors):
        # One tool may serve several operations (two reads, two extractions):
        # each runs under its own clause, so its action is still distinct.
        raise ValueError("invalid_task_draft_binding")
    inputs = owner_inputs(contract)
    operations = []
    for number, (step, descriptor, clause) in enumerate(zip(steps, tools, clauses), 1):
        mine = [v for v in inputs if v.get("operation", 1) == number]
        bindings = [{"argument": v["argument"], "slot": v["slot"]} for v in mine]
        for edge in step.derived:
            field, source, path, bound, form = edge_parts(edge)
            binding = {"argument": field, "slot": result_slot(contract, number, field),
                       "result_of": source, "result_path": list(path), "result_max_bytes": bound}
            if form == LIST:
                binding["result_list"] = True
            elif form is not None:
                binding["result_compute"] = {"op": form[0], "amount": form[1]}
            if edge_candidates(edge) is not None:
                binding["result_candidates"] = list(edge_candidates(edge))
            bindings.append(binding)
        if step.payload_from:
            # A whole-result edge: no path, no bound; the kernel fills the payload.
            payload = next(f["name"] for f in catalog_tool(step.tool)["fields"] if f["role"] == "payload")
            bindings.append({"argument": payload, "slot": result_slot(contract, number, payload),
                             "result_of": step.payload_from})
        bindings.sort(key=lambda b: b["argument"])
        operations.append({"id": number, "clause": clause, "descriptor": descriptor,
            "tool": step.tool, "after": list(range(1, number)), "bindings": bindings})
    # A planner-drafted program is already fixed by the owner's review, so its
    # one-template round needs no request: its view is empty (an address in the
    # request never reaches that model).
    view = b""
    draft = {"schema": 3, "root": ids["root"], "observer_scope": ids["observer"],
        "not_before": not_before, "expires_at": expires_at,
        "operations": operations,
        "templates": [{"id": 1, "order": [o["id"] for o in operations]}],
        "rounds": [{"id": 1, "opens_at": not_before, "advice_cut": not_before,
            "closes_at": expires_at - 1, "advisor": None, "planner": ids["planner"],
            "model_profile": model_profile, "mode": "registered_template_v04",
            "public_view": list(view), "template_ids": [1], "question_codes": [],
            "max_deliveries": 1}],
        "delivery_schedule": [{"id": 1, "round": 1, "role": "planner",
            "opens_at": not_before, "closes_at": expires_at - 1}],
        "release_model_views": True, "max_replacements": 0,
        "final_result_source": operations[-1]["id"],
        "final_release": {"clause": release_clause, "descriptor": ids["release"],
                          "turn": ids["turn"]}}
    return {"contract": contract.document(), "contract_sha256": contract.digest(),
            "task": ids["task"], "planning_draft": draft, "private_inputs": inputs,
            "admitted": False, "production_acceptance": False}
