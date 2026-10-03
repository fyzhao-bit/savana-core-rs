"""Planner-drafted task programs (G3): the untrusted planner proposes the whole
task, the owner side reviews it by fixed rules, and the kernel enforces where
every value comes from.

The planner sees only the owner's request and the reviewed catalog, never a
tool result (as CaMeL's P-LLM). It returns a small program: an ordered list of
reviewed operations, each field given one origin:

    {"text": "..."}              an owner-text literal (a list: items joined by "; ")
    {"from": k}                  the text the quarantined extractor produced at step k
    {"from": k, "path": [...]}   a scalar at a JSON path of step k's tool result
    ... "add_minutes"/"add_days"/"add_amount": n
                                 that text computed by the kernel (a time, date or
                                 amount plus n), n stated by the owner's request

and extraction steps `{"tool": "dojo.model.extract", "source": k, "args":
{"instruction": {"text": ...}, "target": {"text": "<operation>.<field>" | "answer"}}}`
that read step k's whole result as untrusted data and produce one line for the
named target. The last step's result is released to the owner.

Owner review (this module, before anything is signed) refuses a program unless:
every tool is reviewed and served by this suite; every edge points at an earlier
step; no destination (nor a cc/bcc recipient) is derived from a result (the
conservative owner policy: an injection can change what a write says, never
whom it reaches); a text-list field takes typed items (each literal item owner
text; a derived list one bounded edge); a computation's amount is one the
request states (a duration in minutes or days, an amount of money); the program has
at most MAX_STEPS operations; and every literal is owner text (each "; "-separated
item a substring of the request, NFC with whitespace folded) or a value the owner
declares itself: its own dates and times restated as YYYY-MM-DD[ HH:MM], a
boolean or a sharing permission, or a search term / count for a READ tool (never
a URL, which is itself an outbound channel). The extractor's instruction is
always the owner's whole request. The kernel enforces the rule itself on the
schema-2 owner document (a value outside the request and the owner's declared
constants fails before any operation runs) and every signed edge at prepare and
dispatch.
"""
from dataclasses import dataclass
import decimal
import hashlib
import json
import re
import unicodedata

from .agentdojo_provider import canonical
from .agentdojo_tasks import (BENCHMARK, CALENDAR_YEAR, GENERATED_ITEMS, GENERATED_MAX_BYTES, GENERATED_TEXT,
                              GENERATOR_MODEL, LIST, PACKAGE_VERSION, Step, catalog_tool, edge_document,
                              upstream_for)
from .dojo_catalog import (GUARD_ALWAYS, GUARD_FIELD, LIST_KINDS, LIST_SEPARATOR, SENTINELS, decode_argument, entry,
                           suite_operations)

EXTRACT_TOOL = "dojo.model.extract"
ANSWER = "answer"
# An extraction that answers yes or no to a condition the owner's request
# states; its only use is a later write's `when` gate.
CONDITION = "condition"
# The same, answered for the opposite case ("otherwise ..."): yes when the
# owner's condition does NOT hold.
CONDITION_NOT = "condition_not"
CONDITIONS = (CONDITION, CONDITION_NOT)
# The kernel's input runtime authorizes an owner request for 60 s
# (savana-input-runtime: now + 60_000 ms); every step of a plan must finish
# inside it. At about six seconds a step, eight steps fit and twelve do not
# (G11 runs: longer plans stopped at ~64 s without publication), so the
# limit stays at eight; the window itself is the owner's to change.
MAX_STEPS = 8
RESULT_PREFIX = ("result", "content", "0", "text", "$json")
# A tool result's whole text, as an extraction's context (a second source).
RESULT_TEXT = ("result", "content", "0", "text")
MAX_EDGE_BYTES = 512
MAX_CONTEXT_BYTES = 8192
# The extractor's final answer is bounded by its provider at 2000 bytes.
MAX_ANSWER_BYTES = 2048
CONTEXT_FIELDS = ("context", "context2", "context3", "context4", "context5")
MAX_CONTEXTS = len(CONTEXT_FIELDS)
MAX_DECLARED = 32
# Models the owner may name for the quarantined extractor (a signed constant).
EXTRACTOR_MODELS = (GENERATOR_MODEL, "deepseek-v4-pro")
# Read parameters the planner may choose itself (a search term, a count): a read
# has no effect, and its result reaches a write only through a signed edge. A
# URL is excluded: fetching an address is itself an outbound channel.
OWNER_ONLY_READ_FIELDS = frozenset({("dojo.web.get", "url")})
# Recipients beyond a write's one destination field: never derived either.
OWNER_ONLY_WRITE_FIELDS = frozenset({("dojo.email.send", "cc"), ("dojo.email.send", "bcc")})
# A computation's amount, as the planner writes it -> (kernel op, unit scale).
COMPUTE_KEYS = {"add_minutes": "add_minutes", "add_days": "add_days", "add_amount": "add_cents"}
STEP_NOTES = frozenset({"description", "instruction", "comment", "note"})
MAX_PATH = 8
MAX_LIST_ITEMS = 32


def review_policy():
    """What the owner's fixed review admits, as a document an armed benchmark
    batch binds (the programs themselves are drafted per episode)."""
    return {"schema": "savana-drafted-review-v1", "max_steps": MAX_STEPS, "literals": "owner_text",
            "destinations": "owner_text_only", "edges": "earlier_steps_only", "extract_tool": EXTRACT_TOOL,
            "extract_targets_sha256": hashlib.sha256(canonical(list(extract_targets()))).hexdigest(),
            "edge_max_bytes": MAX_EDGE_BYTES, "context_max_bytes": MAX_CONTEXT_BYTES,
            "restated": "owner dates/times (CALENDAR_YEAR default) and end times from stated durations, "
                        "booleans, permissions, read terms except URLs",
            "list_fields": "typed items; each literal item owner text", "computations": sorted(COMPUTE_KEYS),
            "compute_amounts": "magnitude stated in the request",
            "calendar_year": CALENDAR_YEAR, "max_declared": MAX_DECLARED,
            "extract_instruction": "the whole request",
            "conditions": "a write may be gated by a yes/no extraction of owner-text condition; "
                          "a gated step's result is never used"}


class ProgramRefused(ValueError):
    """The owner's fixed review refused a drafted program; nothing is signed.

    ``str(error)`` is the fixed rule code. ``step`` / ``field`` locate it in the
    planner's own program (never data), so a retry can say where it failed."""
    step = None
    field = None


def nfc(text):
    return unicodedata.normalize("NFC", text)


def folded(text):
    """NFC with every whitespace run (line breaks included) as one space."""
    return " ".join(nfc(text).split())


def owner_item(item, prompt):
    """One list item: a non-empty substring of the request as a whole (the
    kernel's per-item rule; an item is never split again)."""
    return type(item) is str and bool(folded(item)) and folded(item) in folded(prompt)


def owner_text(text, prompt):
    """Empty, or every "; "-separated item a non-empty substring of the request,
    both compared NFC-normalized with whitespace runs folded to one space."""
    if type(text) is not str:
        return False
    if text == "":
        return True
    request = folded(prompt)
    return all(folded(item) and folded(item) in request for item in text.split(LIST_SEPARATOR))


_MONTHS = {m: i for i, m in enumerate(("january", "february", "march", "april", "may", "june", "july", "august",
                                        "september", "october", "november", "december"), 1)}
_MONTHS.update({m[:3]: i for m, i in list(_MONTHS.items())})
_MONTH = r"(?P<month>" + "|".join(sorted(_MONTHS, key=len, reverse=True)) + r")\.?"
_DAY = r"(?P<day>[0-3]?[0-9])(?:st|nd|rd|th)?"
_DATE_FORMS = (
    re.compile(_MONTH + r"\s+" + _DAY + r"(?:,?\s+(?P<year>(?:19|20)[0-9]{2}))?\b", re.I),
    re.compile(r"\b(?:the\s+)?" + _DAY + r"\s+of\s+" + _MONTH + r"(?:,?\s+(?P<year>(?:19|20)[0-9]{2}))?\b", re.I),
    re.compile(r"\b(?P<year>(?:19|20)[0-9]{2})-(?P<month>[01][0-9])-(?P<day>[0-3][0-9])\b"),
)
_TIME = re.compile(r"\b(?P<hour>[01]?[0-9]|2[0-3])(?::(?P<minute>[0-5][0-9]))?\s*(?P<half>[ap]\.?m\.?)?(?![0-9])", re.I)


def owner_normalized(prompt):
    """The owner restating the dates and times of its OWN request in the tools'
    form, by a fixed rule (never from a result or a model): each stated date as
    YYYY-MM-DD (CALENDAR_YEAR when the request gives no year), and each such
    date with each stated clock time as "YYYY-MM-DD HH:MM". Relative dates and
    computed times (an end from a duration) are not restated."""
    text = nfc(prompt)
    dates = set()
    for form in _DATE_FORMS:
        for m in form.finditer(text):
            month = m.group("month")
            month = int(month) if month.isdigit() else _MONTHS[month.lower()]
            day, year = int(m.group("day")), int(m.group("year") or CALENDAR_YEAR)
            if 1 <= month <= 12 and 1 <= day <= 31:
                dates.add(f"{year:04d}-{month:02d}-{day:02d}")
    times = set()
    for m in _TIME.finditer(text):
        hour, minute, half = int(m.group("hour")), m.group("minute"), m.group("half")
        if minute is None and half is None:
            continue  # a bare number is not a clock time
        if half:
            if not 1 <= hour <= 12:
                continue
            hour = hour % 12 + (12 if half.lower().startswith("p") else 0)
        times.add(f"{hour:02d}:{int(minute or 0):02d}")
    stamps = {f"{d} {t}" for d in dates for t in times}
    # An end the owner states as a duration from its own start ("a 1-hour
    # event at 10:00") is restated as that end, by the same fixed rule.
    from .agentdojo_tasks import apply_compute
    ends = set()
    for stamp in stamps:
        for minutes in owner_amounts(prompt)["add_minutes"]:
            try:
                ends.add(apply_compute(("add_minutes", minutes), stamp))
            except ValueError:
                pass
    return frozenset(dates | stamps | ends)


_NUMBER_WORDS = {"a": 1, "an": 1, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
                 "eight": 8, "nine": 9, "ten": 10, "twelve": 12, "fifteen": 15, "twenty": 20, "thirty": 30,
                 "forty-five": 45, "half an": 0.5, "half a": 0.5}
_COUNT = r"(?P<count>[0-9]+(?:\.[0-9]+)?|" + "|".join(sorted(map(re.escape, _NUMBER_WORDS), key=len, reverse=True)) + r")"
_DURATION = re.compile(r"\b" + _COUNT + r"[\s-]*(?P<unit>hours?|hrs?|minutes?|mins?|days?|weeks?)\b", re.I)
_MONEY = re.compile(r"(?<![0-9.])(?P<amount>[0-9]{1,9}(?:\.[0-9]{1,2})?)(?![0-9])")


def owner_amounts(prompt):
    """The computation amounts the owner's request states, by a fixed rule:
    durations as minutes (hours, minutes) and days (days, weeks), and every
    plain number as an amount of money in hundredths. Signs are not restated:
    a computation may add or subtract a stated magnitude."""
    text = nfc(prompt)
    minutes, days = set(), set()
    for m in _DURATION.finditer(text):
        count = m.group("count").lower()
        count = _NUMBER_WORDS[count] if count in _NUMBER_WORDS else float(count)
        unit = m.group("unit").lower()
        if unit.startswith(("hour", "hr")):
            value = count * 60
            minutes.add(value)
        elif unit.startswith("min"):
            minutes.add(count)
        elif unit.startswith("day"):
            days.add(count)
        else:
            days.add(count * 7)
    cents = {round(float(m.group("amount")) * 100) for m in _MONEY.finditer(text)}
    def whole(values):
        return {int(v) for v in values if float(v).is_integer() and v > 0}
    return {"add_minutes": whole(minutes), "add_days": whole(days), "add_cents": {c for c in cents if c > 0}}


def extract_targets():
    """Every label an extraction step may name: a non-fixed field of a reviewed
    operation, the owner's final answer, or a yes/no condition. Labels are
    inert vocabulary."""
    from .dojo_catalog import CATALOG
    labels = [ANSWER, *CONDITIONS]
    for tool in CATALOG:
        labels += [f"{tool['operation']}.{name}" for name, _r, _u, kind in tool["fields"]
                   if kind not in ("fixed", "guard")]
    return tuple(labels)


@dataclass(frozen=True)
class DraftedContract:
    """A reviewed planner program for one official task, scored by that task's
    official oracle with its own prompt."""
    suite: str
    task_id: str
    prompt: str
    chain: tuple[Step, ...]
    program: str  # canonical JSON of the planner's program, kept as evidence
    restated: tuple[str, ...] = ()  # owner-declared values the program uses

    variant = "drafted"

    @property
    def contract_id(self):
        return f"{self.task_id}:drafted:{self.digest()[:16]}"

    def steps(self):
        return self.chain

    def constants(self):
        """Owner-declared non-request values: the deployment's fixed synthetic
        controls and the extraction labels this program names."""
        values = {SENTINELS["calendar"], SENTINELS["to"], *self.restated}
        for step in self.chain:
            if step.tool == EXTRACT_TOOL:
                values |= {step.value_map()[k] for k in ("model", "target", "source")}
            elif step.value_map().get(GUARD_FIELD) == GUARD_ALWAYS:
                values.add(GUARD_ALWAYS)
        return sorted(values)

    def document(self):
        return {"schema": "savana-agentdojo-drafted-chain-v1", "benchmark": BENCHMARK, "suite": self.suite,
                "package": PACKAGE_VERSION, "task": self.task_id, "prompt": self.prompt,
                "origin": "owner_text", "program": self.program,
                "steps": [{"tool": st.tool, "upstream_tool": st.upstream_tool,
                           "effect": catalog_tool(st.tool)["effect"], "values": st.value_map(),
                           "payload_from": st.payload_from,
                           "derived": [edge_document(e) for e in st.derived]}
                          for st in self.chain],
                "maximum_attempts": 1, "final_output": "last_step_result"}

    def digest(self):
        return hashlib.sha256(canonical({k: v for k, v in self.document().items() if k != "program"})).hexdigest()


def _refuse(reason):
    raise ProgramRefused(reason)


def _origin(value):
    if type(value) is str:
        # A bare string is the planner's shorthand for a literal; it is held
        # to exactly the same owner-text rule.
        return ("text", value)
    if type(value) is bool:
        return ("text", "true" if value else "false")
    if type(value) is int:
        return ("text", str(value))
    if type(value) is list:
        return ("items", value)
    if type(value) is not dict or not value or set(value) - {"text", "from", "path", *COMPUTE_KEYS}:
        _refuse("field_origin")
    if "text" in value:
        if set(value) != {"text"} or type(value["text"]) not in (str, list):
            _refuse("field_origin")
        return ("items", value["text"]) if type(value["text"]) is list else ("text", value["text"])
    source = value.get("from")
    if type(source) is not int or isinstance(source, bool):
        _refuse("edge_source")
    path = value.get("path")
    if path is not None and (type(path) is not list or not 1 <= len(path) <= MAX_PATH
                             or any(type(p) not in (str, int) or isinstance(p, bool) for p in path)):
        _refuse("edge_path")
    keys = [k for k in COMPUTE_KEYS if k in value]
    compute = None
    if len(keys) > 1:
        _refuse("edge_compute")
    if keys:
        amount = value[keys[0]]
        if type(amount) not in (int, float) or isinstance(amount, bool):
            _refuse("edge_compute")
        # An amount of money is written in units and signed in hundredths.
        scaled = decimal.Decimal(str(amount)) * (100 if keys[0] == "add_amount" else 1)
        if scaled != scaled.to_integral_value():
            _refuse("edge_compute")
        compute = (COMPUTE_KEYS[keys[0]], int(scaled))
    return ("from", source, None if path is None else tuple(str(p) for p in path), compute)


def review_program(*, suite, suite_tools, task_id, prompt, program, bindings=(), extractor_model=GENERATOR_MODEL):
    """The owner's fixed review of a planner program -> DraftedContract, or
    ProgramRefused. `suite_tools` are the official function names this
    episode's suite serves. A refusal carries the step number and field name
    (of the planner's own program) where it occurred. `bindings` are the
    placeholders of a value-blind planner view, each bound to the owner's own
    value before review (`value_blind.bind_program`), so everything below
    judges and signs only the owner's real text. `extractor_model` is the
    owner's choice of model for every extraction step (a signed constant)."""
    if extractor_model not in EXTRACTOR_MODELS:
        raise ValueError("extractor_model")
    where = {"step": None, "field": None}
    if bindings:
        from .value_blind import bind_program
        program = bind_program(program, bindings)
    try:
        return _review_program(where, suite=suite, suite_tools=suite_tools, task_id=task_id, prompt=prompt,
                               program=program, extractor_model=extractor_model)
    except ProgramRefused as error:
        error.step, error.field = where["step"], where["field"]
        raise


def _review_program(where, *, suite, suite_tools, task_id, prompt, program, extractor_model):
    if type(program) is not dict or set(program) != {"steps"} or type(program["steps"]) is not list:
        _refuse("program_shape")
    raw_steps = program["steps"]
    if not 1 <= len(raw_steps) <= MAX_STEPS:
        _refuse("program_length")
    served = set(suite_operations(suite_tools)) | {EXTRACT_TOOL}
    labels = set(extract_targets())
    restatable = owner_normalized(prompt)
    restated = set()
    chain, kinds = [], []
    gated = set()  # steps whose effect a condition decides: their result is never used
    conditions, gates = set(), set()  # condition extractions, and those some gate uses

    def usable(source):
        """An earlier step another may draw on: not a gated one."""
        if source in gated:
            _refuse("gated_result_used")
        return source
    for number, raw in enumerate(raw_steps, 1):
        where["step"], where["field"] = number, None
        # Explanatory notes on a step are ignored, never used as values.
        if type(raw) is not dict or not {"tool", "args"} <= set(raw) <= {"tool", "args", "source", "when"} | STEP_NOTES:
            _refuse("step_shape")
        tool, args = raw["tool"], raw["args"]
        if tool not in served or type(args) is not dict:
            _refuse("unserved_tool")
        values, derived, payload_from = {}, [], 0
        if tool == EXTRACT_TOOL:
            source = raw.get("source")
            if (type(source) is not int or isinstance(source, bool) or not 1 <= source < number
                    or not {"target"} <= set(args) <= {"instruction", "target", "context", "condition"}
                    or "when" in raw):
                _refuse("extract_shape")
            usable(source)
            where["field"] = "target"
            target = _origin(args["target"])
            if target[0] != "text":
                _refuse("extract_target")
            label = target[1]
            if label not in labels:
                # An inert label written without its full prefix names the one
                # catalog field it uniquely ends with.
                matches = [known for known in labels if known.endswith("." + label)]
                if len(matches) != 1:
                    _refuse("extract_target")
                label = matches[0]
            target = ("text", label)
            # A condition target carries the condition, copied from the
            # owner's request; any other target carries none.
            where["field"] = "condition"
            question = ""
            if label in CONDITIONS:
                condition = _origin(args.get("condition"))
                if condition[0] != "text" or not condition[1] or not owner_text(condition[1], prompt):
                    _refuse("condition_text")
                question = condition[1]
            elif "condition" in args:
                _refuse("condition_text")
            if label in CONDITIONS:
                conditions.add(number)
            # The extractor's instruction is always the owner's whole request;
            # whatever the planner wrote there is not used.
            values = {"instruction": folded(prompt), "target": target[1], "model": extractor_model,
                      "to": SENTINELS["to"], "source": str(source), "question": question}
            payload_from = source
            # Up to MAX_CONTEXTS other earlier steps as context, one signed edge
            # each, so one answer can combine several results.
            raw_contexts = args.get("context")
            raw_contexts = ([] if raw_contexts is None else raw_contexts if type(raw_contexts) is list
                            else [raw_contexts])
            contexts = []
            where["field"] = "context"
            for raw_context in raw_contexts:
                context = _origin(raw_context)
                if context[0] == "from" and context[1] == source and context[2] is None:
                    # The source's result is already the payload: the same
                    # result again as context adds nothing, so it is dropped.
                    continue
                # Context is only ever an earlier step's value or result,
                # never a literal.
                if (context[0] != "from" or context[2] is not None or context[3] is not None
                        or not 1 <= context[1] < number or context[1] in contexts):
                    _refuse("extract_context")
                contexts.append(usable(context[1]))
            if len(contexts) > MAX_CONTEXTS:
                _refuse("extract_context")
            for field, earlier in zip(CONTEXT_FIELDS, contexts + [None] * MAX_CONTEXTS):
                if earlier is None:
                    values[field] = ""
                elif kinds[earlier - 1] == "extract":
                    # An earlier answer is only ever more context for a later
                    # extraction (data for the model, never a control), so a
                    # request with several parts can be answered in full.
                    answer = chain[earlier - 1].value_map()["target"] == ANSWER
                    derived.append((field, earlier, GENERATED_TEXT, MAX_ANSWER_BYTES if answer else MAX_EDGE_BYTES))
                else:
                    # Another tool result, whole, as bounded text.
                    derived.append((field, earlier, RESULT_TEXT, MAX_CONTEXT_BYTES))
        else:
            if "source" in raw:
                _refuse("source_on_tool")
            reading = catalog_tool(tool)["effect"] == "read"
            fields = {name: (role, kind) for name, role, _u, kind in entry(tool)["fields"]}
            open_fields = {n for n, (_r, k) in fields.items() if k not in ("fixed", "guard")}
            if set(args) - open_fields:
                _refuse("unknown_field")
            def decodable(value):
                """A literal the field's reviewed decode rule accepts; anything
                else would only fail at the adapter, after earlier steps ran."""
                try:
                    decode_argument(kind, list(value) if type(value) is tuple else value)
                    return True
                except ValueError:
                    return False

            def owned(literal):
                """An owner literal (or one list item) as the owner accepts it."""
                if owner_text(literal, prompt):
                    return True
                if (literal in restatable
                        or (kind in ("boolean", "opt_boolean") and literal in ("true", "false"))
                        or (kind == "permission" and literal in ("r", "rw"))
                        or (reading and (tool, name) not in OWNER_ONLY_READ_FIELDS
                            and 0 < len(literal.encode()) <= 128 and literal == literal.strip()
                            and not any(ord(ch) < 32 for ch in literal))):
                    # Restated by the owner (its own dates/times, a yes/no, a
                    # permission) or a read term the owner accepts from the
                    # planner; declared to the kernel as constants.
                    restated.add(literal)
                    return True
                return False

            if "when" in raw and GUARD_FIELD not in fields:
                where["field"] = "when"
                _refuse("gate_shape")
            for name, (role, kind) in sorted(fields.items()):
                where["field"] = name
                if kind == "fixed":
                    values[name] = SENTINELS[name]
                    continue
                if kind == "guard":
                    # The owner's condition gate: always, or a signed edge from
                    # an earlier yes/no extraction of an owner-text condition.
                    gate = raw.get("when")
                    if gate is None:
                        values[name] = GUARD_ALWAYS
                        continue
                    if (type(gate) is not int or isinstance(gate, bool) or not 1 <= gate < number
                            or kinds[gate - 1] != "extract"
                            or chain[gate - 1].value_map()["target"] not in CONDITIONS):
                        _refuse("gate_source")
                    derived.append((name, gate, GENERATED_TEXT, MAX_EDGE_BYTES))
                    gated.add(number)
                    gates.add(gate)
                    continue
                listed = kind in LIST_KINDS
                if name not in args:
                    if not kind.startswith("opt_") and kind not in ("attachments", "null_text"):
                        _refuse("missing_field")
                    values[name] = () if listed else ""
                    continue
                origin = _origin(args[name])
                if origin[0] in ("text", "items"):
                    if not listed:
                        if origin[0] == "items":
                            _refuse("field_origin")
                        if not owned(origin[1]):
                            _refuse("literal_not_owner_text")
                        if not decodable(origin[1]):
                            _refuse("literal_kind")
                        values[name] = origin[1]
                        continue
                    # A list literal: typed items, each held to the owner rule
                    # by itself (the kernel checks every item the same way).
                    items = (origin[1] if origin[0] == "items" else
                             [] if origin[1] == "" else origin[1].split(LIST_SEPARATOR))
                    if (len(items) > MAX_LIST_ITEMS or any(type(i) is not str or not i or i != i.strip()
                                                           for i in items)):
                        _refuse("literal_list")
                    if not all(owner_item(i, prompt) or (owned(i) and LIST_SEPARATOR not in i) for i in items):
                        _refuse("literal_not_owner_text")
                    if items and not decodable(tuple(items)):
                        _refuse("literal_kind")
                    values[name] = tuple(items)
                    continue
                if role == "destination" or (tool, name) in OWNER_ONLY_READ_FIELDS | OWNER_ONLY_WRITE_FIELDS:
                    # Whom a write reaches, or which address a fetch contacts,
                    # is never chosen by data an injection could control.
                    _refuse("derived_destination")
                _kind, source, path, compute = origin
                if not 1 <= source < number:
                    _refuse("edge_source")
                usable(source)
                if compute is not None:
                    # Only one text is computed, by an amount the request states.
                    if listed or abs(compute[1]) not in owner_amounts(prompt)[compute[0]]:
                        _refuse("compute_amount")
                if kinds[source - 1] == "extract":
                    if path is not None:
                        _refuse("edge_path")
                    if chain[source - 1].value_map()["target"] == ANSWER:
                        # The final answer is unbounded prose; a value a later
                        # field uses comes from an extraction for that field.
                        _refuse("answer_used_as_value")
                    if chain[source - 1].value_map()["target"] in CONDITIONS:
                        # A yes/no answer only ever gates a write.
                        _refuse("condition_used_as_value")
                    full = GENERATED_ITEMS if listed else GENERATED_TEXT
                else:
                    if path is None:
                        _refuse("edge_path")
                    full = RESULT_PREFIX + path
                form = LIST if listed else compute
                derived.append((name, source, full, MAX_EDGE_BYTES) + (() if form is None else (form,)))
        kinds.append("extract" if tool == EXTRACT_TOOL else catalog_tool(tool)["effect"])
        chain.append(Step(tool, upstream_for(tool), tuple(sorted(values.items())), tuple(derived), payload_from))
    for number in sorted(conditions - gates):
        # A condition no action depends on decides nothing: the action the
        # request makes conditional is missing its "when".
        where["step"], where["field"] = number, "condition"
        _refuse("unused_condition")
    where["step"], where["field"] = None, None
    contract = DraftedContract(suite, task_id, prompt, tuple(chain), canonical(program).decode("utf-8"),
                               tuple(sorted(restated)))
    if len(contract.constants()) > MAX_DECLARED or any(len(c.encode()) > 128 for c in contract.constants()):
        _refuse("too_many_declared_values")
    return contract



def parse_program_text(text):
    """The planner's raw reply -> program dict (JSON only, one object)."""
    if type(text) is not str or len(text.encode()) > 16384:
        _refuse("program_text")
    body = text.strip()
    if body.startswith("```"):
        body = body.strip("`")
        body = body[body.find("{"):]
    try:
        value = json.loads(body)
    except ValueError:
        _refuse("program_json")
    return value
