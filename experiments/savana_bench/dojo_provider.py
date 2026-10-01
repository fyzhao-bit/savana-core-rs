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
from .agentdojo_tasks import PACKAGE_VERSION
from .dojo_catalog import SENTINELS, entry, official_call, suite_operations

_FIXED_DOC = {
    "body": "Must be empty; never parsed as code or tool arguments.",
    "calendar": "Fixed primary resource control.",
    "to": "Fixed private result destination control.",
}


def _adapter_source(pyname, operation):
    names = sorted(f[0] for f in entry(operation)["fields"])
    fixed = {f[0] for f in entry(operation)["fields"] if f[3] == "fixed"}
    doc = ['    """Reviewed AgentDojo operation with fixed synthetic controls.', '']
    for name in names:
        doc.append(f"    :param {name}: "
                   + (_FIXED_DOC[name] if name in fixed else "Exact text covered by the signed owner root."))
    doc.append('    """')
    arguments = "{" + ", ".join(f"{n!r}: {n}" for n in names) + "}"
    return "\n".join([
        f"def {pyname}({', '.join(f'{n}: str' for n in names)}):", *doc,
        f"    upstream, official = official_call({operation!r}, {arguments})",
        "    result, error = original.run_function(environment, upstream, official, raise_on_error=False)",
        "    if error is not None:",
        "        raise RuntimeError('upstream_failure')",
        "    return result",
    ])


def dojo_provider(suite, environment, *, max_calls=1, generator=None):
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
    return AgentDojoProvider(FunctionsRuntime(functions), environment, max_calls=max_calls)
