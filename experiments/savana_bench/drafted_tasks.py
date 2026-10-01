"""Planner-drafted task programs (G3): the untrusted planner proposes the whole
task, the owner side reviews it by fixed rules, and the kernel enforces where
every value comes from.

The planner sees only the owner's request and the reviewed catalog, never a
tool result (as CaMeL's P-LLM). It returns a small program: an ordered list of
reviewed operations, each field given one origin:

    {"text": "..."}              an owner-text literal
    {"from": k}                  the text the quarantined extractor produced at step k
    {"from": k, "path": [...]}   a scalar at a JSON path of step k's tool result

and extraction steps `{"tool": "dojo.model.extract", "source": k, "args":
{"instruction": {"text": ...}, "target": {"text": "<operation>.<field>" | "answer"}}}`
that read step k's whole result as untrusted data and produce one line for the
named target. The last step's result is released to the owner.

Owner review (this module, before anything is signed) refuses a program unless:
every tool is reviewed and served by this suite; every edge points at an earlier
step; no destination is derived from a result (the conservative owner policy: an
injection can change what a write says, never whom it reaches); the program has
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
import hashlib
import json
import re
import unicodedata

from .agentdojo_provider import canonical
from .agentdojo_tasks import (BENCHMARK, CALENDAR_YEAR, GENERATED_MAX_BYTES, GENERATED_TEXT, GENERATOR_MODEL,
                              PACKAGE_VERSION, Step, catalog_tool, upstream_for)
from .dojo_catalog import LIST_SEPARATOR, SENTINELS, entry, suite_operations

EXTRACT_TOOL = "dojo.model.extract"
ANSWER = "answer"
MAX_STEPS = 8
RESULT_PREFIX = ("result", "content", "0", "text", "$json")
# A tool result's whole text, as an extraction's context (a second source).
RESULT_TEXT = ("result", "content", "0", "text")
MAX_EDGE_BYTES = 512
MAX_CONTEXT_BYTES = 8192
MAX_DECLARED = 32
# Read parameters the planner may choose itself (a search term, a count): a read
# has no effect, and its result reaches a write only through a signed edge. A
# URL is excluded: fetching an address is itself an outbound channel.
OWNER_ONLY_READ_FIELDS = frozenset({("dojo.web.get", "url")})
STEP_NOTES = frozenset({"description", "instruction", "comment", "note"})
MAX_PATH = 8


def review_policy():
    """What the owner's fixed review admits, as a document an armed benchmark
    batch binds (the programs themselves are drafted per episode)."""
    return {"schema": "savana-drafted-review-v1", "max_steps": MAX_STEPS, "literals": "owner_text",
            "destinations": "owner_text_only", "edges": "earlier_steps_only", "extract_tool": EXTRACT_TOOL,
            "extract_targets_sha256": hashlib.sha256(canonical(list(extract_targets()))).hexdigest(),
            "edge_max_bytes": MAX_EDGE_BYTES, "context_max_bytes": MAX_CONTEXT_BYTES,
            "restated": "owner dates/times (CALENDAR_YEAR default), booleans, permissions, read terms except URLs",
            "calendar_year": CALENDAR_YEAR, "max_declared": MAX_DECLARED,
            "extract_instruction": "the whole request"}


class ProgramRefused(ValueError):
    """The owner's fixed review refused a drafted program; nothing is signed."""


def nfc(text):
    return unicodedata.normalize("NFC", text)


def folded(text):
    """NFC with every whitespace run (line breaks included) as one space."""
    return " ".join(nfc(text).split())


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
    return frozenset(dates | {f"{d} {t}" for d in dates for t in times})


def extract_targets():
    """Every label an extraction step may name: a non-fixed field of a reviewed
    operation, or the owner's final answer. Labels are inert vocabulary."""
    from .dojo_catalog import CATALOG
    labels = [ANSWER]
    for tool in CATALOG:
        labels += [f"{tool['operation']}.{name}" for name, _r, _u, kind in tool["fields"] if kind != "fixed"]
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
                values |= {step.value_map()["model"], step.value_map()["target"]}
        return sorted(values)

    def document(self):
        return {"schema": "savana-agentdojo-drafted-chain-v1", "benchmark": BENCHMARK, "suite": self.suite,
                "package": PACKAGE_VERSION, "task": self.task_id, "prompt": self.prompt,
                "origin": "owner_text", "program": self.program,
                "steps": [{"tool": st.tool, "upstream_tool": st.upstream_tool,
                           "effect": catalog_tool(st.tool)["effect"], "values": dict(st.values),
                           "payload_from": st.payload_from,
                           "derived": [{"field": f, "source_operation": src, "path": list(path),
                                        "max_bytes": bound} for f, src, path, bound in st.derived]}
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
    if type(value) is not dict or not value or set(value) - {"text", "from", "path"}:
        _refuse("field_origin")
    if "text" in value:
        if set(value) != {"text"} or type(value["text"]) is not str:
            _refuse("field_origin")
        return ("text", value["text"])
    source = value.get("from")
    if type(source) is not int or isinstance(source, bool):
        _refuse("edge_source")
    path = value.get("path")
    if path is not None and (type(path) is not list or not 1 <= len(path) <= MAX_PATH
                             or any(type(p) not in (str, int) or isinstance(p, bool) for p in path)):
        _refuse("edge_path")
    return ("from", source, None if path is None else tuple(str(p) for p in path))


def review_program(*, suite, suite_tools, task_id, prompt, program):
    """The owner's fixed review of a planner program -> DraftedContract, or
    ProgramRefused. `suite_tools` are the official function names this
    episode's suite serves."""
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
    for number, raw in enumerate(raw_steps, 1):
        # Explanatory notes on a step are ignored, never used as values.
        if type(raw) is not dict or not {"tool", "args"} <= set(raw) <= {"tool", "args", "source"} | STEP_NOTES:
            _refuse("step_shape")
        tool, args = raw["tool"], raw["args"]
        if tool not in served or type(args) is not dict:
            _refuse("unserved_tool")
        values, derived, payload_from = {}, [], 0
        if tool == EXTRACT_TOOL:
            source = raw.get("source")
            if (type(source) is not int or isinstance(source, bool) or not 1 <= source < number
                    or not {"target"} <= set(args) <= {"instruction", "target", "context"}):
                _refuse("extract_shape")
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
            # The extractor's instruction is always the owner's whole request;
            # whatever the planner wrote there is not used.
            values = {"instruction": folded(prompt), "target": target[1], "model": GENERATOR_MODEL,
                      "to": SENTINELS["to"]}
            payload_from = source
            if "context" in args:
                # Context is only ever an earlier extraction's value, so one
                # answer can combine several results; never a literal.
                context = _origin(args["context"])
                if context[0] != "from" or context[2] is not None or not 1 <= context[1] < number:
                    _refuse("extract_context")
                if kinds[context[1] - 1] == "extract":
                    if chain[context[1] - 1].value_map()["target"] == ANSWER:
                        _refuse("answer_used_as_value")
                    derived.append(("context", context[1], GENERATED_TEXT, MAX_EDGE_BYTES))
                else:
                    # A second tool result, whole, as bounded text.
                    derived.append(("context", context[1], RESULT_TEXT, MAX_CONTEXT_BYTES))
            else:
                values["context"] = ""
        else:
            if "source" in raw:
                _refuse("source_on_tool")
            reading = catalog_tool(tool)["effect"] == "read"
            fields = {name: (role, kind) for name, role, _u, kind in entry(tool)["fields"]}
            open_fields = {n for n, (_r, k) in fields.items() if k != "fixed"}
            if set(args) - open_fields:
                _refuse("unknown_field")
            for name, (role, kind) in sorted(fields.items()):
                if kind == "fixed":
                    values[name] = SENTINELS[name]
                    continue
                if name not in args:
                    if not kind.startswith("opt_") and kind not in ("attachments", "null_text"):
                        _refuse("missing_field")
                    values[name] = ""
                    continue
                origin = _origin(args[name])
                if origin[0] == "text":
                    literal = origin[1]
                    if owner_text(literal, prompt):
                        pass
                    elif (literal in restatable
                          or (kind in ("boolean", "opt_boolean") and literal in ("true", "false"))
                          or (kind == "permission" and literal in ("r", "rw"))
                          or (reading and (tool, name) not in OWNER_ONLY_READ_FIELDS
                              and 0 < len(literal.encode()) <= 128 and literal == literal.strip()
                              and not any(ord(ch) < 32 for ch in literal))):
                        # Restated by the owner (its own dates/times, a yes/no,
                        # a permission) or a read term the owner accepts from
                        # the planner; declared to the kernel as constants.
                        restated.add(literal)
                    else:
                        _refuse("literal_not_owner_text")
                    values[name] = literal
                    continue
                if role == "destination" or (tool, name) in OWNER_ONLY_READ_FIELDS:
                    # Whom a write reaches, or which address a fetch contacts,
                    # is never chosen by data an injection could control.
                    _refuse("derived_destination")
                _kind, source, path = origin
                if not 1 <= source < number:
                    _refuse("edge_source")
                if kinds[source - 1] == "extract":
                    if path is not None:
                        _refuse("edge_path")
                    if chain[source - 1].value_map()["target"] == ANSWER:
                        # The final answer is unbounded prose; a value a later
                        # field uses comes from an extraction for that field.
                        _refuse("answer_used_as_value")
                    full = GENERATED_TEXT
                else:
                    if path is None:
                        _refuse("edge_path")
                    full = RESULT_PREFIX + path
                derived.append((name, source, full, MAX_EDGE_BYTES))
        kinds.append("extract" if tool == EXTRACT_TOOL else catalog_tool(tool)["effect"])
        chain.append(Step(tool, upstream_for(tool), tuple(sorted(values.items())), tuple(derived), payload_from))
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
