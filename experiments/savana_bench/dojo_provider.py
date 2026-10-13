"""Provider semantics for the full reviewed AgentDojo catalog, one suite per episode.

The endpoint AFTER execd, not a planner tool executor or authorization server.
It serves exactly the reviewed operations whose official function belongs to
this episode's suite (`dojo_catalog.suite_operations`), plus the quarantined
generator when one is supplied. Each adapter takes the kernel's text fields,
checks every fixed synthetic field against its sentinel, decodes the others by
their reviewed rule (`dojo_catalog.official_call`) and runs the ORIGINAL
AgentDojo function once. Hostile text in any field is data: it is never parsed
as a tool call, and no field can name a different function.

Three things are no longer this provider's to do; the kernel's executor does
them before a request reaches it: a guarded write whose condition does not
hold is answered by the executor and never sent here; the compute step
(`dojo.compute.table`) is evaluated by the executor and never sent here; and a
model tool deployed with the model codec arrives with every sensitive value
already masked (and its reply is unmasked by the executor). The extractor only
tells its model what a placeholder is when it sees one.
"""
import importlib.metadata
import json

from .agentdojo_provider import AgentDojoProvider
from .agentdojo_tasks import GENERATOR_MODEL, PACKAGE_VERSION
from .dojo_catalog import (COMPUTED_SOURCE, GUARD_FIELD, LIST_KINDS, LIST_SEPARATOR, SENTINELS, entry, guard_holds,
                           official_call, suite_operations)

ANSWER_BYTES = 2000
FIELD_BYTES = 480
_FORMATS = {
    "text": "one line of plain text", "opt_text": "one line of plain text",
    "null_text": "one line of plain text", "number": "a decimal number such as 12.5 (digits, at most one '.')",
    "opt_number": "a decimal number such as 12.5 (digits, at most one '.')", "integer": "a whole number",
    "opt_integer": "a whole number", "boolean": "true or false", "opt_boolean": "true or false",
    "permission": "exactly r (read) or rw (read and write)", "list": f"the items separated by '{LIST_SEPARATOR}'",
    "opt_list": f"the items separated by '{LIST_SEPARATOR}'",
    "attachments": f"file ids separated by '{LIST_SEPARATOR}'",
}

_FIXED_DOC = {
    GUARD_FIELD: "Owner condition gate: 'always', or an earlier extraction's yes/no answer.",
    "body": "Must be empty; never parsed as code or tool arguments.",
    "calendar": "Fixed primary resource control.",
    "to": "Fixed private result destination control.",
}


def _adapter_source(pyname, operation):
    names = sorted(f[0] for f in entry(operation)["fields"])
    fixed = {f[0] for f in entry(operation)["fields"] if f[3] in ("fixed", "guard")}
    guarded = any(f[3] == "guard" for f in entry(operation)["fields"])
    listed = {f[0] for f in entry(operation)["fields"] if f[3] in LIST_KINDS}
    doc = ['    """Reviewed AgentDojo operation with fixed synthetic controls.', '']
    for name in names:
        doc.append(f"    :param {name}: "
                   + (_FIXED_DOC[name] if name in fixed else "Exact text covered by the signed owner root."))
    doc.append('    """')
    arguments = "{" + ", ".join(f"{n!r}: {n}" for n in names) + "}"
    return "\n".join([
        f"def {pyname}({', '.join(f'{n}: list[str]' if n in listed else f'{n}: str' for n in names)}):", *doc,
        # The executor answers a gate that does not hold itself; one reaching
        # this adapter is refused, never performed.
        *([f"    if not guard_holds({GUARD_FIELD}):", "        raise ValueError('condition_not_held')"]
          if guarded else []),
        f"    upstream, official = official_call({operation!r}, {arguments})",
        "    result, error = original.run_function(environment, upstream, official, raise_on_error=False)",
        "    if error is not None:",
        "        raise RuntimeError('upstream_failure')",
        "    return result",
    ])


def target_kind(target):
    """The reviewed kind of a field label ("answer" for the final answer,
    "multi" for several fields of one operation joined by the separator)."""
    if target in ("answer", "condition", "condition_not"):
        return target
    if LIST_SEPARATOR in target:
        return "multi"
    operation, _, name = target.rpartition(".")
    spec = next((f for f in entry(operation)["fields"] if f[0] == name and f[3] != "fixed"), None)
    if spec is None:
        raise ValueError("extract_target")
    return spec[3]


def target_description(target, functions, question=""):
    """(what the extractor must produce, its byte bound) for a reviewed label:
    the owner's final answer, a yes/no answer to a condition the owner's
    request states (`question`, owner text), or one official argument of a
    catalog field."""
    if target == "answer":
        return ("The final answer to the owner's request, stating all the requested information "
                "completely and concisely in plain text.", ANSWER_BYTES)
    if target == "condition":
        return ("Whether this condition from the owner's request holds, judged only from SOURCE and CONTEXT: "
                f"\"{question}\". Reply with exactly yes or no.", FIELD_BYTES)
    if target == "condition_not":
        return ("Whether this condition from the owner's request is FALSE, judged only from SOURCE and CONTEXT: "
                f"\"{question}\". Reply with exactly yes (it is false) or no (it holds).", FIELD_BYTES)
    if LIST_SEPARATOR in target:
        labels = target.split(LIST_SEPARATOR)
        names = [label.rpartition(".")[2] for label in labels]
        parts = " ".join(f'"{name}": {target_description(label, functions)[0]}' for name, label in zip(names, labels))
        return ("Several values, as ONE JSON object on a single line with exactly the keys "
                + ", ".join(f'"{name}"' for name in names) + ", each value a JSON string. " + parts,
                ANSWER_BYTES)
    operation, _, name = target.rpartition(".")
    spec = next((f for f in entry(operation)["fields"] if f[0] == name and f[3] != "fixed"), None)
    if spec is None:
        raise ValueError("extract_target")
    _name, _role, upstream_arg, kind = spec
    function = functions[entry(operation)["upstream"]]
    official = function.parameters.model_json_schema().get("properties", {}).get(upstream_arg, {})
    meaning = " ".join(str(official.get("description", "")).split()) or upstream_arg
    return (f"The argument '{upstream_arg}' for the function {function.name}: {meaning} "
            f"Format: {_FORMATS[kind]}.", FIELD_BYTES)


def source_step(source):
    """(step number, whether the owner's program says it is a computation)
    of an extraction's `source` constant, or a ValueError."""
    step, computed = (source[:-len(COMPUTED_SOURCE)], True) if source.endswith(COMPUTED_SOURCE) else (source, False)
    if not (step.isascii() and step.isdigit() and step[0] != "0"):
        raise ValueError("generator_control_mismatch")
    return int(step), computed


def _extract_parts(arguments, functions):
    """The extractor model's inputs for one call's arguments as this provider
    received them: (instruction, source, target description, byte bound,
    context, note)."""
    from .quarantined_generator import EXACT_NOTE
    from .value_blind import EXTRACT_NOTE, PLACEHOLDER
    contexts = [arguments.get(c, "") for c in ("context", "context2", "context3", "context4", "context5")]
    context = "\n\n".join(c for c in contexts if c)
    question = arguments.get("question", "")
    _step, computed = source_step(arguments["source"])
    masked = any(PLACEHOLDER.search(text) for text in (arguments["instruction"], arguments["body"], context, question))
    description, max_bytes = target_description(arguments["target"], functions, question)
    note = (EXTRACT_NOTE if masked else "") + (EXACT_NOTE if computed else "")
    return arguments["instruction"], arguments["body"], description, max_bytes, context, note


def extract_request(arguments, functions):
    """(the exact body the extractor's model is sent, the byte bound) for one
    `dojo.model.extract` call's arguments as this provider received them
    (already masked by the executor under the model codec). Pure, so the
    offline verifier recomputes what left the host from the provider's own
    record of the call."""
    from .quarantined_generator import generator_request_body
    instruction, source, description, max_bytes, context, note = _extract_parts(arguments, functions)
    body = generator_request_body(model=arguments["model"], instruction=instruction, source=source,
                                  target=description, max_bytes=max_bytes, context=context, note=note)
    return body, max_bytes


def _extract_tool(generator, functions):
    """The reviewed `dojo.model.extract` adapter: the payload is the earlier
    result the kernel passed (data), the instruction is the owner's text, the
    target an inert catalog label; model/destination controls are fixed.

    Deployed with the model codec, every text arrives with the leak gate's
    spans as placeholders (the kernel's executor masked them, one table per
    call) and the executor puts the values back into this adapter's reply; the
    model is told what a placeholder is only when one is present. An
    extraction whose owner-signed source is a computation tells the model to
    state that value as given (EXACT_NOTE)."""
    def extract(body: str, context: str, context2: str, context3: str, context4: str, context5: str,
                instruction: str, model: str, question: str, source: str, target: str, to: str):
        """Quarantined extraction of one value from an untrusted source; no tools, no actions.

        :param body: The earlier verified result, passed by the kernel as data.
        :param context: An earlier step's value or result (a signed edge) or empty.
        :param context2: A second such context or empty.
        :param context3: A third such context or empty.
        :param context4: A fourth such context or empty.
        :param context5: A fifth such context or empty.
        :param instruction: The owner's own request text.
        :param model: Fixed generator model control.
        :param question: The owner's condition text for a yes/no target, or empty.
        :param source: The step whose result is the payload (an owner-signed number, ":computed" for a computation).
        :param target: The reviewed label of the value to produce.
        :param to: Fixed private result destination control.
        """
        # The signed model control must be the one this connector's model serves.
        if model != getattr(generator, "model", GENERATOR_MODEL) or to != SENTINELS["to"] or not body or not instruction:
            raise ValueError("generator_control_mismatch")
        arguments = dict(body=body, context=context, context2=context2, context3=context3, context4=context4,
                         context5=context5, instruction=instruction, model=model, question=question, source=source,
                         target=target)
        sent_instruction, sent_source, description, max_bytes, sent_context, note = _extract_parts(arguments, functions)
        # A note is passed only with placeholders or a computed source: any other call is unchanged.
        line = generator(instruction=sent_instruction, source=sent_source, target=description, max_bytes=max_bytes,
                         context=sent_context, **(dict(note=note) if note else {}))
        if target_kind(target) == "multi":
            # One JSON object with exactly the target's field names, each value
            # one bounded line; anything else fails the step (nothing is guessed).
            names = [label.rpartition(".")[2] for label in target.split(LIST_SEPARATOR)]
            try:
                value = json.loads(line)
            except ValueError:
                raise ValueError("extract_fields") from None
            if (type(value) is not dict or set(value) != set(names)
                    or any(type(v) not in (str, int, float) or isinstance(v, bool) for v in value.values())):
                raise ValueError("extract_fields")
            from .quarantined_generator import bounded_line
            return {"text": line, "fields": {name: bounded_line(str(value[name]), FIELD_BYTES) for name in names}}
        if target_kind(target) not in LIST_KINDS:
            return {"text": line}
        # A list target: the same line, and its items split by the reviewed
        # separator (a fixed rule; the items are as untrusted as the line).
        items = [item.strip() for item in line.split(LIST_SEPARATOR.strip())]
        return {"text": line, "items": [item for item in items if item]}

    extract.__name__ = "dojo.model.extract"
    return extract


def dojo_provider(suite, environment, *, max_calls=1, generator=None):
    """The provider for one episode of `suite` (an AgentDojo TaskSuite).

    Only the original functions of that suite back an operation; an operation
    of another suite, the compute step (the kernel's executor evaluates it), or
    the generator when none is supplied, is not served (a call to it fails
    before any effect)."""
    from agentdojo.functions_runtime import FunctionsRuntime, make_function

    if importlib.metadata.version("agentdojo") != PACKAGE_VERSION:
        raise ValueError("agentdojo_version_not_reviewed")
    if generator is not None and not callable(generator):
        raise ValueError("generator_not_callable")
    tools = {t.name: t for t in suite.tools}
    original = FunctionsRuntime(list(tools.values()))
    namespace = {"original": original, "environment": environment, "official_call": official_call,
                 "guard_holds": guard_holds,
                 "SENTINELS": SENTINELS}
    functions = []
    for operation in suite_operations(tools):
        pyname = f"reviewed_tool_{len(functions)}"
        exec(_adapter_source(pyname, operation), namespace)
        adapter = namespace.pop(pyname)
        adapter.__name__ = operation
        functions.append(make_function(adapter))
    if generator is not None:
        functions.append(make_function(_extract_tool(generator, tools)))
    return AgentDojoProvider(FunctionsRuntime(functions), environment, max_calls=max_calls)
