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
every tool is reviewed and served by this suite; every literal is empty or an
owner-text constant (each "; "-separated item an NFC substring of the request);
every edge points at an earlier step; no destination is derived from a result
(the conservative owner policy: an injection can change what a write says, never
whom it reaches); and the program has at most MAX_STEPS operations. The kernel
enforces the owner-text rule itself on the schema-2 owner document (a value
outside the request and the owner's declared constants fails before any
operation runs) and every signed edge at prepare and dispatch.
"""
from dataclasses import dataclass
import hashlib
import json
import unicodedata

from .agentdojo_provider import canonical
from .agentdojo_tasks import (BENCHMARK, GENERATED_MAX_BYTES, GENERATED_TEXT, GENERATOR_MODEL, PACKAGE_VERSION,
                              Step, catalog_tool, upstream_for)
from .dojo_catalog import LIST_SEPARATOR, SENTINELS, entry, suite_operations

EXTRACT_TOOL = "dojo.model.extract"
ANSWER = "answer"
MAX_STEPS = 6
RESULT_PREFIX = ("result", "content", "0", "text", "$json")
MAX_EDGE_BYTES = 512
MAX_PATH = 8


class ProgramRefused(ValueError):
    """The owner's fixed review refused a drafted program; nothing is signed."""


def nfc(text):
    return unicodedata.normalize("NFC", text)


def owner_text(text, prompt):
    """Empty, or every "; "-separated item an NFC substring of the request."""
    if type(text) is not str:
        return False
    if text == "":
        return True
    request = nfc(prompt)
    return all(item and nfc(item) in request for item in text.split(LIST_SEPARATOR))


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

    variant = "drafted"

    @property
    def contract_id(self):
        return f"{self.task_id}:drafted:{self.digest()[:16]}"

    def steps(self):
        return self.chain

    def constants(self):
        """Owner-declared non-request values: the deployment's fixed synthetic
        controls and the extraction labels this program names."""
        values = {SENTINELS["calendar"], SENTINELS["to"]}
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
    chain, kinds = [], []
    for number, raw in enumerate(raw_steps, 1):
        if type(raw) is not dict or not {"tool", "args"} <= set(raw) <= {"tool", "args", "source"}:
            _refuse("step_shape")
        tool, args = raw["tool"], raw["args"]
        if tool not in served or type(args) is not dict:
            _refuse("unserved_tool")
        values, derived, payload_from = {}, [], 0
        if tool == EXTRACT_TOOL:
            source = raw.get("source")
            if (type(source) is not int or isinstance(source, bool) or not 1 <= source < number
                    or set(args) != {"instruction", "target"}):
                _refuse("extract_shape")
            instruction, target = _origin(args["instruction"]), _origin(args["target"])
            if instruction[0] != "text" or target[0] != "text" or not instruction[1].strip():
                _refuse("extract_literals")
            if not owner_text(instruction[1], prompt):
                _refuse("instruction_not_owner_text")
            if target[1] not in labels:
                _refuse("extract_target")
            values = {"instruction": instruction[1], "target": target[1], "model": GENERATOR_MODEL,
                      "to": SENTINELS["to"]}
            payload_from = source
        else:
            if "source" in raw:
                _refuse("source_on_tool")
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
                    if not owner_text(origin[1], prompt):
                        _refuse("literal_not_owner_text")
                    values[name] = origin[1]
                    continue
                if role == "destination":
                    _refuse("derived_destination")
                _kind, source, path = origin
                if not 1 <= source < number:
                    _refuse("edge_source")
                if kinds[source - 1] == "extract":
                    if path is not None:
                        _refuse("edge_path")
                    full = GENERATED_TEXT
                else:
                    if path is None:
                        _refuse("edge_path")
                    full = RESULT_PREFIX + path
                derived.append((name, source, full, MAX_EDGE_BYTES))
        kinds.append("extract" if tool == EXTRACT_TOOL else catalog_tool(tool)["effect"])
        chain.append(Step(tool, upstream_for(tool), tuple(sorted(values.items())), tuple(derived), payload_from))
    return DraftedContract(suite, task_id, prompt, tuple(chain),
                           canonical(program).decode("utf-8"))


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
