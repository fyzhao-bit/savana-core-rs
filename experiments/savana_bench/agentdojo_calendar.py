"""Strict provider semantics for the reviewed workspace read-tool adapters.

This is the endpoint AFTER execd, not a planner tool executor or authorization
server. Its in-process fixture transport supplies no production authentication.
Only original AgentDojo read functions run, one per reviewed catalog operation;
arbitrary runtime/tool fallbacks are not exposed. Input text, including hostile
text, is never parsed as a tool call. The set of served operations and their
business fields is exactly the reviewed TOOL_CATALOG, so the provider stays in
lockstep with the signed descriptors the deployment generator ships.
"""
import importlib.metadata

from .agentdojo_provider import AgentDojoProvider
from .agentdojo_tasks import PACKAGE_VERSION, TOOL_CATALOG

# The synthetic business controls every adapter fixes; they are never forwarded
# to an official function and never interpreted as code or tool arguments.
_CONTROL_DOC = {
    "body": "Must be empty; never parsed as code or tool arguments.",
    "calendar": "Fixed primary workspace resource control.",
    "to": "Fixed private result destination control.",
}


def _wrapper_source(pyname, upstream, params):
    """Generate a real adapter function body (not a dynamic signature) so that
    agentdojo.make_function introspects it exactly like a hand-written tool."""
    signature = ", ".join(["body: str", "calendar: str",
                           *[f"{p}: str" for p in params], "to: str"])
    forwarded = ", ".join(f'"{p}": {p}' for p in params)
    doc = ['    """Reviewed workspace read operation with fixed business controls.', '']
    for name in ("body", "calendar", *params, "to"):
        doc.append(f'    :param {name}: '
                   + _CONTROL_DOC.get(name, "Exact value covered by the signed owner root."))
    doc.append('    """')
    return "\n".join([
        f"def {pyname}({signature}):",
        *doc,
        "    check_controls(body, calendar, to)",
        f"    result, error = original.run_function(environment, {upstream!r}, "
        f"{{{forwarded}}}, raise_on_error=False)",
        "    if error is not None:",
        "        raise RuntimeError('upstream_read_failure')",
        "    return result",
    ])


def calendar_provider(environment):
    from agentdojo.default_suites.v1.tools.calendar_client import (
        get_day_calendar_events, search_calendar_events,
    )
    from agentdojo.default_suites.v1.tools.email_client import (
        get_unread_emails, search_emails,
    )
    from agentdojo.default_suites.v1.tools.cloud_drive_client import (
        list_files, search_files, search_files_by_filename,
    )
    from agentdojo.functions_runtime import FunctionsRuntime, make_function

    if importlib.metadata.version("agentdojo") != PACKAGE_VERSION:
        raise ValueError("agentdojo_version_not_reviewed")
    # Only these original read functions may back a reviewed operation. A catalog
    # entry naming anything else is refused rather than silently ignored.
    upstream_impls = {f.__name__: f for f in (
        get_day_calendar_events, search_calendar_events, get_unread_emails,
        search_emails, list_files, search_files, search_files_by_filename)}
    needed, seen = [], set()
    for _, upstream, _ in TOOL_CATALOG:
        if upstream not in upstream_impls:
            raise ValueError("unreviewed_upstream_function")
        if upstream not in seen:
            seen.add(upstream)
            needed.append(make_function(upstream_impls[upstream]))
    # The official tool schema is resolved before any episode request. Returning
    # an upstream exception is indeterminate, not proof of no effect or safety.
    original = FunctionsRuntime(needed)

    def check_controls(body, calendar, to):
        if body != "" or calendar != "primary" or to != "private-result":
            raise ValueError("workspace_adapter_control_mismatch")

    namespace = {"original": original, "environment": environment,
                 "check_controls": check_controls}
    functions = []
    for operation, upstream, params in TOOL_CATALOG:
        pyname = f"reviewed_tool_{len(functions)}"
        exec(_wrapper_source(pyname, upstream, params), namespace)
        adapter = namespace.pop(pyname)
        adapter.__name__ = operation
        functions.append(make_function(adapter))
    runtime = FunctionsRuntime(functions)
    return AgentDojoProvider(runtime, environment, max_calls=1)
