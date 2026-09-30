"""Strict provider semantics for reviewed calendar task adapters.

This is the endpoint AFTER execd, not a planner tool executor or authorization
server. Its in-process fixture transport supplies no production authentication.
Only original AgentDojo read functions run; arbitrary runtime/tool fallbacks are
not exposed. Input text, including hostile text, is never parsed as a tool call.
"""
import importlib.metadata

from .agentdojo_provider import AgentDojoProvider
from .agentdojo_tasks import PACKAGE_VERSION


def calendar_provider(environment):
    from agentdojo.default_suites.v1.tools.calendar_client import (
        get_day_calendar_events, search_calendar_events,
    )
    from agentdojo.functions_runtime import FunctionsRuntime, make_function

    if importlib.metadata.version("agentdojo") != PACKAGE_VERSION:
        raise ValueError("agentdojo_version_not_reviewed")
    # The official tool schema is resolved before any episode request. Returning
    # an upstream exception is indeterminate, not proof of no effect or safety.
    original = FunctionsRuntime([make_function(get_day_calendar_events),
                                 make_function(search_calendar_events)])

    def check_controls(body, calendar, to):
        if body != "" or calendar != "primary" or to != "private-result":
            raise ValueError("calendar_adapter_control_mismatch")

    def search(body: str, calendar: str, date: str, query: str, to: str):
        """Read matching calendar events; no raw upstream kwargs or write tools.

        :param body: Must be empty; not interpreted as code or tool arguments.
        :param calendar: Fixed primary calendar resource.
        :param date: Exact ISO date covered by the signed root.
        :param query: Exact search term covered by the signed root.
        :param to: Fixed private result destination.
        """
        check_controls(body, calendar, to)
        result, error = original.run_function(environment, "search_calendar_events",
            {"date": date, "query": query}, raise_on_error=False)
        if error is not None:
            raise RuntimeError("upstream_calendar_failure")
        return result

    def day(body: str, calendar: str, day: str, to: str):
        """Read the calendar appointments on one exact authorized day.

        :param body: Must be empty; not interpreted as code or tool arguments.
        :param calendar: Fixed primary calendar resource.
        :param day: Exact ISO date covered by the signed root.
        :param to: Fixed private result destination.
        """
        check_controls(body, calendar, to)
        result, error = original.run_function(environment, "get_day_calendar_events",
            {"day": day}, raise_on_error=False)
        if error is not None:
            raise RuntimeError("upstream_calendar_failure")
        return result

    search.__name__ = "dojo.calendar.search"
    day.__name__ = "dojo.calendar.day"
    runtime = FunctionsRuntime([make_function(search), make_function(day)])
    return AgentDojoProvider(runtime, environment, max_calls=1)
