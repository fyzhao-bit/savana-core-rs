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
schema-3 owner document before any operation runs: every input is request
text for every field it fills (a destination, cc or bcc only as a whole token
of the request), or a constant the owner bound to exactly that operation and
field (never a destination); a deployment-fixed field takes only its fixed
value. Every signed edge is enforced again at prepare and dispatch.
"""
from dataclasses import dataclass
import decimal
import hashlib
import json
import re
import unicodedata

from .agentdojo_provider import canonical
from .agentdojo_tasks import (BENCHMARK, CALENDAR_YEAR, GENERATED_ITEMS, GENERATED_TEXT,
                              GENERATOR_MODEL, LIST, PACKAGE_VERSION, Step, catalog_tool, edge_document,
                              upstream_for)
from .dojo_catalog import (COMPUTED_SOURCE, GUARD_ALWAYS, GUARD_FIELD, LIST_KINDS, LIST_SEPARATOR, SENTINELS,
                           decode_argument, entry,
                           suite_operations)
from .dojo_compute import (CALC, COMPUTE_TOOL, FIELDS as COMPUTE_FIELDS, INPUT_FIELDS, ComputeSpecError,
                           calc_constants, validate_spec)

# Reads whose whole result exceeds a compute input's signed bound
# (MAX_CONTEXT_BYTES) in the benchmark environments (list_files: about 29 KB
# of file contents); the edge could never be derived, so the plan would stall.
LARGE_RESULT_TOOLS = frozenset({"dojo.file.list"})

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
# inside it. At about six seconds a step (G11), eight steps fit and twelve did
# not. Steps now take about four seconds: in the F5 runs an eight-step program
# was released a median 37 s (at most 40 s) after the episode was bound, so
# ten steps fit with margin. The window itself is the owner's to change.
MAX_STEPS = 10
# One extraction may produce several fields of one operation (U3), each used
# through its own signed edge: fewer steps for a call that needs them all.
MULTI_FIELDS = (2, 4)
MULTI_PREFIX = ("result", "content", "0", "text", "$json", "fields")
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
    return {"schema": "savana-drafted-review-v2", "max_steps": MAX_STEPS, "literals": "owner_text",
            "destinations": "owner text, each item a whole token of the request (cc and bcc too); never a constant",
            "constants": "each bound to the (operation, field) it fills; fixed synthetic fields are the "
                         "deployment's, not constants",
            "write_destination": "always named, even where optional",
            "edges": "earlier_steps_only", "extract_tool": EXTRACT_TOOL,
            "multi_field_extraction": f"{MULTI_FIELDS[0]}-{MULTI_FIELDS[1]} non-list fields of one operation, "
                                      "each used through its own edge by name",
            "extract_targets_sha256": hashlib.sha256(canonical(list(extract_targets()))).hexdigest(),
            "edge_max_bytes": MAX_EDGE_BYTES, "context_max_bytes": MAX_CONTEXT_BYTES,
            "restated": "owner dates/times (CALENDAR_YEAR default) and end times from stated durations, "
                        "booleans, permissions, read terms except URLs",
            "list_fields": "typed items; each literal item owner text", "computations": sorted(COMPUTE_KEYS),
            "compute_amounts": "magnitude stated in the request",
            "calendar_year": CALENDAR_YEAR, "max_declared": MAX_DECLARED,
            "extract_instruction": "the whole request",
            "conditions": "a write may be gated by a yes/no extraction of owner-text condition; "
                          "a gated step's result is never used",
            "compute": {"tool": COMPUTE_TOOL, "inputs": "signed edges to earlier results",
                        "spec": "filter/order/output texts in a fixed grammar, declared as owner constants",
                        "output": "data: never a destination, used only through a signed edge",
                        "calc": "only where the run allows it: exact arithmetic on the first number of each "
                                "input (#1..#4) with + - * / ( ) min max, no filter or order; every number it "
                                "writes is stated in the request, or is 2 or 100; an extraction of a computation "
                                "names its source <step>:computed",
                        "evaluated_by": "the kernel's executor (codec TableComputeV1), never a provider"},
            "final_answer": "only where the run asks for it: a program whose last result is data (a read, a "
                            "computation, an extracted field), or an action after an earlier answer, ends with the "
                            "owner's own extraction of the final answer from up to 6 earlier results (never a "
                            "condition or a write's result; a large result only as its source), so it may have "
                            "max_steps + 1 steps; the completion never refuses a program"}


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


# Characters that join the parts of one address ("alice.bob@x.com",
# "www.x.com/page"); any other non-alphanumeric character separates tokens.
_JOINS = frozenset(".@-_/:+%#~=&?")


def _continues(side, after=False):
    """Whether the characters on one side of a match (nearest first) continue
    it: a letter or digit, directly or after one joining character. After the
    match, a period and then a capital letter end a sentence written without a
    space ("... www.x.com.They ..."): host names and addresses are lower case."""
    first = next(side, None)
    if first is None:
        return False
    if first.isalnum():
        return True
    if first in _JOINS:
        second = next(side, None)
        if after and first == "." and second is not None and second.isupper():
            return False
        return second is not None and second.isalnum()
    return False


def owner_token(item, prompt):
    """One destination item as the kernel accepts it: request text that is a
    whole token of the request (it cannot be extended by a letter or digit on
    either side, directly or after a joining character), compared NFC with
    whitespace folded. So "bob@company.co" is not taken from "bob@company.com"
    (the kernel's `contains_whole_token`)."""
    if type(item) is not str:
        return False
    request, needle = folded(prompt), folded(item)
    if not any(ch.isalnum() for ch in needle):
        return False
    start = request.find(needle)
    while start != -1:
        if (not _continues(iter(reversed(request[:start])))
                and not _continues(iter(request[start + len(needle):]), after=True)):
            return True
        start = request.find(needle, start + len(needle))
    return False


def owner_destination(text, prompt):
    """A destination text as the kernel accepts it: empty, a whole-token
    item, or every "; "-separated item a whole-token item."""
    if type(text) is not str:
        return False
    return text == "" or owner_token(text, prompt) or all(owner_token(i, prompt) for i in text.split(LIST_SEPARATOR))


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


# The numbers a "calc" output may write besides the request's own: 2 (a half)
# and 100 (a percentage).
CALC_STRUCTURAL = (decimal.Decimal(2), decimal.Decimal(100))


def calc_numbers(prompt):
    """The numbers a "calc" output may write, by a fixed rule: every plain
    number the owner's request states, every number word it uses (not "a" or
    "an"), and CALC_STRUCTURAL."""
    text = nfc(prompt)
    numbers = {decimal.Decimal(m.group("amount")) for m in _MONEY.finditer(text)}
    numbers |= {decimal.Decimal(str(value)) for word, value in _NUMBER_WORDS.items()
                if word not in ("a", "an", "half a", "half an") and re.search(rf"\b{re.escape(word)}\b", text, re.I)}
    return numbers | set(CALC_STRUCTURAL)


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
        """Owner-declared non-request values: the values the review restated
        or accepted, the extraction labels this program names, and the
        `always` gate. The deployment's fixed synthetic controls are not
        constants: the kernel holds each fixed field to its own value."""
        values = set(self.restated)
        for step in self.chain:
            if step.tool == EXTRACT_TOOL:
                values |= {step.value_map()[k] for k in ("model", "target", "source")}
            elif step.value_map().get(GUARD_FIELD) == GUARD_ALWAYS:
                values.add(GUARD_ALWAYS)
        return sorted(values)

    def bound_constants(self):
        """`constants()` as the owner document declares them: each value with
        every (operation, field) of this program it fills, so the kernel
        accepts it there and nowhere else. A destination-class field never
        takes a constant (the kernel refuses one even if bound), so none is
        bound to one."""
        values = set(self.constants())
        places = {}
        for step in self.chain:
            fields = {field["name"]: field for field in catalog_tool(step.tool)["fields"]}
            for name, value in step.values:
                field = fields[name]
                if "fixed" in field or field["role"] in ("destination", "copy_destination"):
                    continue
                for item in (value if type(value) is tuple else (value,)):
                    if item in values:
                        places.setdefault(item, set()).add((step.tool, name))
        return [{"value": value, "fields": [{"operation": operation, "field": field}
                                            for operation, field in sorted(places[value])]}
                for value in sorted(places)]

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


# An action the owner's request asks for: an action verb in request form
# (imperative, or after please / can you / go ahead and / ...). Judged on the
# owner's own text alone, and used only to ask a planner once whether it meant
# to leave the action out (`omitted_write`); it never refuses a program.
_ACTION_VERBS = ("pay", "refund", "send", "transfer", "schedule", "set up", "update", "adjust", "change", "invite",
                 "add", "post", "write", "reply", "message", "create", "reschedule", "append", "delete", "share",
                 "cancel", "book", "reserve", "make a reservation", "remove", "do the actions", "do all the tasks",
                 "follow the instructions")
_ACTION = re.compile(r"(?:^|[.!?:]\s+|\d\.\s+|\b(?:please|can you|could you|would you|go ahead and|make sure to|"
                     r"don'?t forget to|do not forget to|then|also|and|if so,?)\s+)(?:please\s+)?(?P<verb>"
                     + "|".join(map(re.escape, _ACTION_VERBS)) + r")\b", re.I)


def _label_kind(label):
    """The reviewed kind of a field label's catalog field."""
    operation, _, name = label.rpartition(".")
    return next(f[3] for f in entry(operation)["fields"] if f[0] == name)


def extracted_fields(step):
    """The field names a multi-field extraction step produces, in order, or ()."""
    if step.tool != EXTRACT_TOOL or LIST_SEPARATOR not in step.value_map()["target"]:
        return ()
    return tuple(label.rpartition(".")[2] for label in step.value_map()["target"].split(LIST_SEPARATOR))


def _multi_field(step, path):
    """The field of a multi-field extraction a one-segment path names: the
    field itself, or one of the step's target labels (or a dotted suffix of
    one, as `send_money.amount`). None for anything else."""
    if path is None or len(path) != 1 or type(path[0]) is not str:
        return None
    labels = step.value_map()["target"].split(LIST_SEPARATOR)
    named = [label.rpartition(".")[2] for label in labels
             if path[0] in (label, label.rpartition(".")[2]) or label.endswith("." + path[0])]
    return named[0] if len(named) == 1 else None


def requested_action(prompt):
    """The first action verb the owner's request asks for, or None."""
    match = _ACTION.search(" ".join(prompt.split()))
    return None if match is None else match.group("verb").lower()


def _writes(step):
    return step.tool not in (EXTRACT_TOOL, COMPUTE_TOOL) and catalog_tool(step.tool)["effect"] != "read"


def performs_action(contract):
    """Whether a reviewed program has a step that changes state: a write tool
    (extraction and compute steps only read recorded results)."""
    return any(_writes(step) for step in contract.steps())


# The owner's final answer (`+answer=final`): what its inputs may be, in order
# of preference. An earlier answer, a computation and a tool read carry what
# the request asked; an extracted field is mostly an argument for a later call.
FINAL_INPUTS = ("answer", "compute", "read", "fields", "extract")


def _answer_input(raw):
    """A raw step's class for the owner's final answer: a FINAL_INPUTS
    member, "write" (never an input), or None for a condition (decides a
    gate, says nothing the request asked). Raises ValueError (or KeyError for
    an unreviewed tool) on a step the review refuses anyway."""
    if type(raw) is not dict or type(raw.get("args")) is not dict:
        raise ValueError("step_shape")
    if raw.get("tool") == EXTRACT_TOOL:
        try:
            target = _origin(raw["args"].get("target"))
        except ProgramRefused:
            raise ValueError("extract_target") from None
        if target[0] not in ("text", "items"):
            raise ValueError("extract_target")
        if target[0] == "items":
            return "fields"
        return "answer" if target[1] == ANSWER else None if target[1] in CONDITIONS else "extract"
    if raw.get("tool") == COMPUTE_TOOL:
        return "compute"
    return "read" if catalog_tool(raw.get("tool"))["effect"] == "read" else "write"


def ends_with_answer(program):
    """Whether a program's last step extracts the final answer."""
    try:
        return _answer_input(program["steps"][-1]) == "answer"
    except (KeyError, IndexError, TypeError, ValueError):
        return False


def with_final_answer(program):
    """`+answer=final`: the planner's program completed by the owner's own
    last step, the final answer, where the program's last result would not be
    one: it ends in a read, a computation or an extracted field (data, not an
    answer), or in a write after an earlier answer (a question asked before the
    request's action). The step extracts the final answer from up to
    MAX_CONTEXTS + 1 earlier results, by FINAL_INPUTS and most recent first
    within each; never a condition or a write's result. A large result is read
    whole only as the payload (a context's edge is bounded), so at most one is
    used, as the source. A pure function of the program, so the review,
    agentd's structured planning of the completed program and the verifier
    all see the same steps. Any other program, or one the review refuses
    anyway, is returned as it is."""
    if type(program) is not dict or set(program) != {"steps"} or type(program["steps"]) is not list:
        return program
    steps = program["steps"]
    if not 1 <= len(steps) <= MAX_STEPS:
        return program
    try:
        classes = [_answer_input(raw) for raw in steps]
    except (KeyError, TypeError, ValueError):
        return program
    if classes[-1] in ("answer", None) or (classes[-1] == "write" and "answer" not in classes):
        return program
    ranked = [number for kind in FINAL_INPUTS for number in range(len(steps), 0, -1) if classes[number - 1] == kind]
    large = [number for number in ranked if steps[number - 1]["tool"] in LARGE_RESULT_TOOLS]
    inputs = (large[:1] + [number for number in ranked if number not in large])[:MAX_CONTEXTS + 1]
    if not inputs:
        return program
    args = {"target": {"text": ANSWER}}
    if inputs[1:]:
        args["context"] = [{"from": number} for number in inputs[1:]]
    return {"steps": [*steps, {"tool": EXTRACT_TOOL, "source": inputs[0], "args": args}]}


def review_program(*, suite, suite_tools, task_id, prompt, program, bindings=(), extractor_model=GENERATOR_MODEL,
                   derived_destinations=False, read_only=False, destination_candidates=None, calc=False,
                   final_answer=False):
    """The owner's fixed review of a planner program -> DraftedContract, or
    ProgramRefused. `suite_tools` are the official function names this
    episode's suite serves. A refusal carries the step number and field name
    (of the planner's own program) where it occurred. `bindings` are the
    placeholders of a value-blind planner view, each bound to the owner's own
    value before review (`value_blind.bind_program`), so everything below
    judges and signs only the owner's real text. `extractor_model` is the
    owner's choice of model for every extraction step (a signed constant).
    `derived_destinations` (experiments on the kernel's own floor only) is an
    owner who signs a destination or fetched address derived from data, which
    this review otherwise never does. `read_only` is the read turn of
    instructions the owner has not adopted yet (`adopted_instructions`): any
    step that changes state is refused (`read_turn_writes`).
    `destination_candidates` (with `derived_destinations`) is the closed set
    the owner signs into every destination edge data fills, recipients beyond
    the one destination included (a trusted-set origin): the kernel endorses
    a derived destination only if it is a member, byte for byte. `calc`
    admits a compute step's "calc" output (`dojo_compute`), whose numbers must
    be stated in the request (`calc_numbers`). `final_answer` completes the
    program with the owner's final answer (`with_final_answer`) and admits one
    more step when the last is the final answer; a program the completion
    would get refused is reviewed as the planner wrote it (the owner's own
    step never refuses a program)."""
    if extractor_model not in EXTRACTOR_MODELS:
        raise ValueError("extractor_model")
    where = {"step": None, "field": None}
    if bindings:
        from .value_blind import bind_program
        program = bind_program(program, bindings)

    def review(program):
        return _review_program(where, suite=suite, suite_tools=suite_tools, task_id=task_id, prompt=prompt,
                               program=program, extractor_model=extractor_model,
                               derived_destinations=derived_destinations,
                               destination_candidates=destination_candidates, calc=calc,
                               max_steps=MAX_STEPS + 1 if final_answer and ends_with_answer(program) else MAX_STEPS)
    try:
        if destination_candidates is not None and (not derived_destinations or not destination_candidates):
            raise ValueError("destination_candidates")
        completed = with_final_answer(program) if final_answer else program
        try:
            contract = review(completed)
        except ProgramRefused:
            if completed is program:
                raise
            contract = review(program)
    except ProgramRefused as error:
        error.step, error.field = where["step"], where["field"]
        raise
    if read_only and performs_action(contract):
        error = ProgramRefused("read_turn_writes")
        error.step = next(number for number, step in enumerate(contract.steps(), 1) if _writes(step))
        raise error
    return contract


def _review_program(where, *, suite, suite_tools, task_id, prompt, program, extractor_model,
                    derived_destinations=False, destination_candidates=None, calc=False, max_steps=MAX_STEPS):
    if type(program) is not dict or set(program) != {"steps"} or type(program["steps"]) is not list:
        _refuse("program_shape")
    raw_steps = program["steps"]
    if not 1 <= len(raw_steps) <= max_steps:
        _refuse("program_length")
    served = set(suite_operations(suite_tools)) | {EXTRACT_TOOL, COMPUTE_TOOL}
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
            if target[0] not in ("text", "items"):
                _refuse("extract_target")

            def full_label(label):
                if label in labels:
                    return label
                # An inert label written without its full prefix names the one
                # catalog field it uniquely ends with.
                matches = [known for known in labels if known.endswith("." + label)]
                if len(matches) != 1:
                    _refuse("extract_target")
                return matches[0]
            if target[0] == "items":
                # Several fields of ONE operation from the same source, each a
                # single text value a later field takes by its name.
                many = [full_label(item) if type(item) is str else _refuse("extract_target")
                        for item in target[1]]
                operations = {item.rpartition(".")[0] for item in many}
                if (not MULTI_FIELDS[0] <= len(many) <= MULTI_FIELDS[1] or len(set(many)) != len(many)
                        or len(operations) != 1 or set(many) & {ANSWER, *CONDITIONS}
                        or any(_label_kind(item) in LIST_KINDS for item in many)):
                    _refuse("extract_target")
                label = LIST_SEPARATOR.join(many)
            else:
                label = full_label(target[1])
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
            # Where the run allows exact arithmetic, an extraction of a
            # computation says so in its signed source (the extractor states
            # that value as given).
            computed = calc and kinds[source - 1] == "compute"
            values = {"instruction": folded(prompt), "target": target[1], "model": extractor_model,
                      "to": SENTINELS["to"], "source": f"{source}{COMPUTED_SOURCE}" if computed else str(source),
                      "question": question}
            if kinds[source - 1] == "compute":
                # A computation is answered by the kernel's executor itself; the
                # payload is its text, by a signed edge (never the reply's
                # envelope, whose request id only the kernel knows).
                derived.append(("body", source, GENERATED_TEXT, MAX_ANSWER_BYTES))
            else:
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
                    wide = (chain[earlier - 1].value_map()["target"] == ANSWER
                            or bool(extracted_fields(chain[earlier - 1])))
                    derived.append((field, earlier, GENERATED_TEXT, MAX_ANSWER_BYTES if wide else MAX_EDGE_BYTES))
                elif kinds[earlier - 1] == "compute":
                    derived.append((field, earlier, GENERATED_TEXT, MAX_EDGE_BYTES))
                else:
                    # Another tool result, whole, as bounded text.
                    derived.append((field, earlier, RESULT_TEXT, MAX_CONTEXT_BYTES))
        elif tool == COMPUTE_TOOL:
            # A fixed deterministic function of earlier results: its inputs are
            # signed edges, its filter/order/output texts a fixed grammar the
            # owner declares as constants, and its output is data like an
            # extraction's (never a destination; used only through an edge).
            if "source" in raw or "when" in raw or set(args) - set(COMPUTE_FIELDS):
                _refuse("compute_shape")
            given = [name for name in INPUT_FIELDS if name in args]
            where["field"] = "input1"
            if not given or given != list(INPUT_FIELDS[:len(given)]):
                _refuse("compute_input")
            for name in given:
                where["field"] = name
                origin = _origin(args[name])
                if (origin[0] != "from" or origin[2] is not None or origin[3] is not None
                        or not 1 <= origin[1] < number):
                    _refuse("compute_input")
                earlier = usable(origin[1])
                if kinds[earlier - 1] == "extract":
                    label = chain[earlier - 1].value_map()["target"]
                    if extracted_fields(chain[earlier - 1]):
                        # A multi-field extraction feeds a field, never a table.
                        _refuse("compute_input")
                    if label == ANSWER:
                        _refuse("answer_used_as_value")
                    if label in CONDITIONS:
                        _refuse("condition_used_as_value")
                    derived.append((name, earlier, GENERATED_TEXT, MAX_ANSWER_BYTES))
                elif kinds[earlier - 1] == "compute":
                    derived.append((name, earlier, GENERATED_TEXT, MAX_ANSWER_BYTES))
                else:
                    if chain[earlier - 1].tool in LARGE_RESULT_TOOLS:
                        _refuse("compute_large_input")
                    derived.append((name, earlier, RESULT_TEXT, MAX_CONTEXT_BYTES))
            where["field"] = "output"
            try:
                spec = validate_spec(args, len(given), calc=calc)
                # Arithmetic writes numbers of its own: each one the owner stated.
                if spec["output"].startswith(CALC + " ") and not calc_constants(spec["output"], len(given)) <= (
                        calc_numbers(prompt)):
                    _refuse("calc_constant")
            except ComputeSpecError as error:
                _refuse(str(error))
            values = {**{name: "" for name in INPUT_FIELDS[len(given):]}, **spec,
                      "body": SENTINELS["body"], "calendar": SENTINELS["calendar"], "to": SENTINELS["to"]}
            restated |= {text for text in spec.values() if text}
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
                    # A write names who or where it goes even where the operation
                    # lets the field be left out: the kernel confines every
                    # write's destination and refuses an empty one.
                    if role == "destination" and kind == "opt_text" and not reading:
                        _refuse("missing_destination")
                    if not kind.startswith("opt_") and kind not in ("attachments", "null_text"):
                        _refuse("missing_field")
                    values[name] = () if listed else ""
                    continue
                origin = _origin(args[name])
                # A destination (cc and bcc too) is the owner's own words, a
                # whole token of the request; never a declared constant.
                addressing = role in ("destination", "copy_destination")
                if origin[0] in ("text", "items"):
                    if not listed:
                        if origin[0] == "items":
                            _refuse("field_origin")
                        if not (owner_destination(origin[1], prompt) if addressing else owned(origin[1])):
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
                    if not all(owner_token(i, prompt) if addressing
                               else owner_item(i, prompt) or (owned(i) and LIST_SEPARATOR not in i) for i in items):
                        _refuse("literal_not_owner_text")
                    if items and not decodable(tuple(items)):
                        _refuse("literal_kind")
                    values[name] = tuple(items)
                    continue
                if (not derived_destinations
                        and (addressing or (tool, name) in OWNER_ONLY_READ_FIELDS | OWNER_ONLY_WRITE_FIELDS)):
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
                if kinds[source - 1] == "compute":
                    if path is not None:
                        _refuse("edge_path")
                    full = GENERATED_ITEMS if listed else GENERATED_TEXT
                elif kinds[source - 1] == "extract" and extracted_fields(chain[source - 1]):
                    # One field of a multi-field extraction, by its name, or by
                    # the label the target gave it (planners write either): the
                    # signed edge always names the field.
                    field = _multi_field(chain[source - 1], path)
                    if listed or field is None:
                        _refuse("edge_path")
                    full = MULTI_PREFIX + (field,)
                elif kinds[source - 1] == "extract":
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
                if destination_candidates is not None and ((role == "destination" and not reading)
                                                           or (tool, name) in OWNER_ONLY_WRITE_FIELDS):
                    # The owner's signed set: data may choose which member only.
                    derived.append((name, source, full, MAX_EDGE_BYTES, form, tuple(destination_candidates)))
                    continue
                derived.append((name, source, full, MAX_EDGE_BYTES) + (() if form is None else (form,)))
        kinds.append("extract" if tool == EXTRACT_TOOL else "compute" if tool == COMPUTE_TOOL
                     else catalog_tool(tool)["effect"])
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
