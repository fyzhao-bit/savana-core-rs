"""Provider semantics for the full reviewed AgentDojo catalog, one suite per episode.

The endpoint AFTER execd, not a planner tool executor or authorization server.
It serves exactly the reviewed operations whose official function belongs to
this episode's suite (`dojo_catalog.suite_operations`), plus the quarantined
generator when one is supplied. Each adapter takes the kernel's text fields,
checks every fixed synthetic field against its sentinel, decodes the others by
their reviewed rule (`dojo_catalog.official_call`) and runs the ORIGINAL
AgentDojo function once. Hostile text in any field is data: it is never parsed
as a tool call, and no field can name a different function.
"""
import importlib.metadata

from .agentdojo_calendar import _generator_tool
from .agentdojo_provider import AgentDojoProvider
from .agentdojo_tasks import GENERATOR_MODEL, PACKAGE_VERSION
from .dojo_catalog import (GUARD_FIELD, LIST_KINDS, LIST_SEPARATOR, SENTINELS, SKIPPED, entry, guard_holds,
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
        *([f"    if not guard_holds({GUARD_FIELD}):", f"        return {SKIPPED!r}"] if guarded else []),
        f"    upstream, official = official_call({operation!r}, {arguments})",
        "    result, error = original.run_function(environment, upstream, official, raise_on_error=False)",
        "    if error is not None:",
        "        raise RuntimeError('upstream_failure')",
        "    return result",
    ])


def target_kind(target):
    """The reviewed kind of a field label ("answer" for the final answer)."""
    if target in ("answer", "condition"):
        return target
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


def extract_request(arguments, functions, view):
    """(the exact body the extractor's model is sent, the placeholder
    bindings, the byte bound) for one `dojo.model.extract` call's kernel
    arguments under an extractor view (`value_blind.extractor_inputs`). Pure,
    so the offline verifier recomputes what left the host."""
    from .quarantined_generator import generator_request_body
    from .value_blind import EXTRACT_NOTE, extractor_inputs
    contexts = [arguments.get(c, "") for c in ("context", "context2", "context3", "context4", "context5")]
    instruction, source, context, question, bindings = extractor_inputs(
        arguments["instruction"], arguments["body"], "\n\n".join(c for c in contexts if c), view,
        arguments.get("question", ""))
    description, max_bytes = target_description(arguments["target"], functions, question)
    body = generator_request_body(model=arguments["model"], instruction=instruction, source=source,
                                  target=description, max_bytes=max_bytes, context=context,
                                  note=EXTRACT_NOTE if bindings else "")
    return body, bindings, max_bytes


def _extract_tool(generator, functions, view="raw"):
    """The reviewed `dojo.model.extract` adapter: the payload is the earlier
    result the kernel passed (data), the instruction is the owner's text, the
    target an inert catalog label; model/destination controls are fixed.

    Under a masked `view` this connector sends the model the instruction,
    payload and context with the leak gate's spans as placeholders (one table
    per call) and puts the values back into the model's reply. A value put
    back is one of this call's own inputs, so the reply can carry nothing the
    unmasked model could not have copied; it still reaches a later operation
    only through an owner-signed edge, and the kernel bounds it there."""
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
        :param source: The step whose result is the payload (an owner-signed number).
        :param target: The reviewed label of the value to produce.
        :param to: Fixed private result destination control.
        """
        # The signed model control must be the one this connector's model serves.
        if (model != getattr(generator, "model", GENERATOR_MODEL) or to != SENTINELS["to"] or not body
                or not instruction
                or not (source.isascii() and source.isdigit() and source[0] != "0")):
            raise ValueError("generator_control_mismatch")
        contexts = [c for c in (context, context2, context3, context4, context5) if c]
        from .value_blind import EXTRACT_NOTE, bind_text, extractor_inputs
        sent_instruction, sent_source, sent_context, sent_question, bindings = extractor_inputs(
            instruction, body, "\n\n".join(contexts), view, question)
        description, max_bytes = target_description(target, functions, sent_question)
        # The note is passed only with placeholders: a raw call is unchanged.
        line = generator(instruction=sent_instruction, source=sent_source, target=description, max_bytes=max_bytes,
                         context=sent_context, **(dict(note=EXTRACT_NOTE) if bindings else {}))
        if bindings:
            from .quarantined_generator import bounded_line
            line = bounded_line(bind_text(line, bindings), max_bytes)
        if target_kind(target) not in LIST_KINDS:
            return {"text": line}
        # A list target: the same line, and its items split by the reviewed
        # separator (a fixed rule; the items are as untrusted as the line).
        items = [item.strip() for item in line.split(LIST_SEPARATOR.strip())]
        return {"text": line, "items": [item for item in items if item]}

    extract.__name__ = "dojo.model.extract"
    return extract


def dojo_provider(suite, environment, *, max_calls=1, generator=None, extractor_view="raw"):
    """The provider for one episode of `suite` (an AgentDojo TaskSuite).

    Only the original functions of that suite back an operation; an operation
    of another suite, or the generator when none is supplied, is not served
    (a call to it fails before any effect)."""
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
        functions.append(make_function(_generator_tool(generator)))
        functions.append(make_function(_extract_tool(generator, tools, extractor_view)))
    return AgentDojoProvider(FunctionsRuntime(functions), environment, max_calls=max_calls)
