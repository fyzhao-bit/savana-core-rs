"""Strict provider semantics for the reviewed workspace tool adapters.

This is the endpoint AFTER execd, not a planner tool executor or authorization
server. Its in-process fixture transport supplies no production authentication.
Only original AgentDojo functions run, one per reviewed catalog operation
(reads and the reviewed authorizing writes); arbitrary runtime/tool fallbacks are
not exposed. Input text, including hostile text, is never parsed as a tool call.
Every synthetic control field (body/calendar/to) is fixed to its sentinel and
never forwarded; the remaining fields are the official function's own arguments,
which the kernel has already authorized (G4 structure, G5 confinement) before a
request reaches here. The served operations are exactly TOOL_CATALOG (reads) and
WRITE_CATALOG (writes), so the provider stays in lockstep with the signed
descriptors the deployment generator ships.
"""
import importlib.metadata

from .agentdojo_provider import AgentDojoProvider
from .agentdojo_tasks import PACKAGE_VERSION, TOOL_CATALOG, WRITE_CATALOG

# Synthetic business controls, always fixed and never forwarded to an official
# function. A field named here must equal its sentinel; any other field is a
# real official argument forwarded verbatim.
SENTINELS = {"body": "", "calendar": "primary", "to": "private-result"}
_SENTINEL_DOC = {
    "body": "Must be empty; never parsed as code or tool arguments.",
    "calendar": "Fixed primary workspace resource control.",
    "to": "Fixed private result destination control.",
}


def _tool_specs():
    """(operation, upstream, sorted business field names) for every reviewed
    tool. Read fields are body/calendar/to plus the read parameters; write
    fields are the explicit catalog fields (real resource/destination values)."""
    specs = []
    for name, upstream, params in TOOL_CATALOG:
        specs.append((name, upstream, sorted(("body", "calendar", "to", *params))))
    for name, upstream, _effect, fields in WRITE_CATALOG:
        specs.append((name, upstream, sorted(n for n, _role in fields)))
    return specs


def _wrapper_source(pyname, upstream, field_names):
    """Generate a real adapter function body (not a dynamic signature) so that
    agentdojo.make_function introspects it exactly like a hand-written tool."""
    signature = ", ".join(f"{n}: str" for n in field_names)
    sentinel_fields = [n for n in field_names if n in SENTINELS]
    forward = [n for n in field_names if n not in SENTINELS]
    doc = ['    """Reviewed workspace operation with fixed synthetic controls.', '']
    for n in field_names:
        doc.append(f'    :param {n}: '
                   + _SENTINEL_DOC.get(n, "Exact value covered by the signed owner root."))
    doc.append('    """')
    lines = [f"def {pyname}({signature}):", *doc]
    if sentinel_fields:
        guard = " or ".join(f"{n} != SENTINELS[{n!r}]" for n in sentinel_fields)
        lines += [f"    if {guard}:",
                  "        raise ValueError('workspace_adapter_control_mismatch')"]
    forward_dict = "{" + ", ".join(f"{n!r}: {n}" for n in forward) + "}"
    lines += [
        f"    result, error = original.run_function(environment, {upstream!r}, "
        f"{forward_dict}, raise_on_error=False)",
        "    if error is not None:",
        "        raise RuntimeError('upstream_failure')",
        "    return result",
    ]
    return "\n".join(lines)


def calendar_provider(environment, max_calls=1):
    """One call per reviewed operation: a read-only contract gets exactly one,
    a read -> write contract exactly two. Never more than the plan can use."""
    from agentdojo.default_suites.v1.tools.calendar_client import (
        get_day_calendar_events, search_calendar_events,
    )
    from agentdojo.default_suites.v1.tools.email_client import (
        get_unread_emails, search_emails,
    )
    from agentdojo.default_suites.v1.tools.cloud_drive_client import (
        append_to_file, list_files, search_files, search_files_by_filename,
    )
    from agentdojo.functions_runtime import FunctionsRuntime, make_function

    if importlib.metadata.version("agentdojo") != PACKAGE_VERSION:
        raise ValueError("agentdojo_version_not_reviewed")
    # Only these original functions may back a reviewed operation. A catalog
    # entry naming anything else is refused rather than silently ignored.
    upstream_impls = {f.__name__: f for f in (
        get_day_calendar_events, search_calendar_events, get_unread_emails,
        search_emails, list_files, search_files, search_files_by_filename,
        append_to_file)}
    specs = _tool_specs()
    needed, seen = [], set()
    for _, upstream, _fields in specs:
        if upstream not in upstream_impls:
            raise ValueError("unreviewed_upstream_function")
        if upstream not in seen:
            seen.add(upstream)
            needed.append(make_function(upstream_impls[upstream]))
    # The official tool schema is resolved before any episode request. Returning
    # an upstream exception is indeterminate, not proof of no effect or safety.
    original = FunctionsRuntime(needed)

    namespace = {"original": original, "environment": environment, "SENTINELS": SENTINELS}
    functions = []
    for operation, upstream, field_names in specs:
        pyname = f"reviewed_tool_{len(functions)}"
        exec(_wrapper_source(pyname, upstream, field_names), namespace)
        adapter = namespace.pop(pyname)
        adapter.__name__ = operation
        functions.append(make_function(adapter))
    runtime = FunctionsRuntime(functions)
    return AgentDojoProvider(runtime, environment, max_calls=max_calls)
