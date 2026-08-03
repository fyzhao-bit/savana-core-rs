import asyncio
import inspect
import threading
import time

import pytest

import savana
import savana_core


CORE_TYPES = {
    "Identity",
    "Client",
    "Session",
    "Handle",
    "MaskedView",
    "Plan",
    "PlanStep",
    "ApprovalRequest",
    "ExecutionResult",
    "ConnectorDescriptor",
    "IntentPrivacy",
    "ContentKind",
    "RunLimits",
    "AgentEvent",
    "SavanaError",
    "AuthError",
    "ApprovalDenied",
    "PolicyRefused",
}

SESSION_METHODS = {
    "ingest_text",
    "ingest_file",
    "read_view",
    "run_planner",
    "execute",
    "run_agent",
    "release",
    "register_connector",
    "remove_connector",
    "list_connectors",
    "revoke",
    "close",
}


def public_methods(cls):
    return {
        name
        for name in vars(cls)
        if not name.startswith("_") and callable(getattr(cls, name))
    }


def scripted_session(*, delay_seconds=0.0):
    return savana.Session._from_core(
        savana_core._debug_scripted_session(delay_seconds=delay_seconds)
    )


def transport_session(*, delay_seconds=0.0):
    return savana.Session._from_core(
        savana_core._debug_transport_session(delay_seconds=delay_seconds)
    )


def test_public_surface_is_exactly_the_approved_types_and_business_methods():
    assert set(savana.__all__) == CORE_TYPES
    assert public_methods(savana.Identity) == {"load"}
    assert public_methods(savana.Client) == {"session", "enroll"}
    assert public_methods(savana.Session) == SESSION_METHODS
    assert "fetch" not in vars(savana.Session)
    assert list(inspect.signature(savana.Session.run_planner).parameters) == [
        "self",
        "intent_privacy",
    ]
    assert list(inspect.signature(savana.Session.ingest_text).parameters) == [
        "self",
        "text",
        "content_kind",
    ]
    assert list(inspect.signature(savana.Session.release).parameters) == [
        "self",
        "document",
        "approval",
    ]


def test_choices_and_exception_inheritance_are_stable():
    assert savana.IntentPrivacy.PRIVATE.value == "private"
    assert savana.IntentPrivacy.THIRD_PARTY.value == "third_party"
    assert savana.ContentKind.CHAT_TEXT.value == "chat_text"
    assert savana.ContentKind.PLAIN_TEXT.value == "plain_text"
    assert savana.ContentKind.PARSED_DOCUMENT.value == "parsed_document"
    assert issubclass(savana.AuthError, savana.SavanaError)
    assert issubclass(savana.ApprovalDenied, savana.SavanaError)
    assert issubclass(savana.PolicyRefused, savana.SavanaError)


def test_errors_expose_stable_codes_without_paths(tmp_path):
    with pytest.raises(savana.SavanaError) as limits_error:
        savana.RunLimits(0, 1, 1.0)
    assert limits_error.value.code == "invalid_request"

    missing = tmp_path / "private-identity.json"
    with pytest.raises(savana.AuthError) as auth_error:
        savana.Identity.load(missing)
    assert auth_error.value.code == "authentication_failed"
    assert str(missing) not in str(auth_error.value)


def test_capability_values_are_non_forgeable_and_redacted():
    with pytest.raises(TypeError):
        savana.Identity(object())
    with pytest.raises(TypeError):
        savana.Session(object())
    with pytest.raises(TypeError):
        savana.Handle(b"forged capability")

    handle = savana_core._debug_handle("document")
    rendered = repr(handle)
    assert rendered == "Handle(<opaque:document>)"
    assert "666f72676564" not in rendered
    for forbidden in ("bytes", "raw", "canonical", "cbor", "base64", "to_bytes"):
        assert not hasattr(handle, forbidden)

    step = savana_core._debug_plan().steps[0]
    assert repr(step) == "PlanStep(Handle(<opaque:plan-step>))"
    assert not hasattr(step, "kind")
    assert not hasattr(step, "reads")
    assert not hasattr(step, "effect")


def test_approval_request_and_connector_projection_are_truthful_and_opaque():
    request = savana_core._debug_approval_request()
    assert request.display == "Approve exact operation"
    assert request.purpose == "tool_execution"
    assert "Approve exact operation" not in repr(request)
    assert not hasattr(request, "recipients")

    assert not hasattr(savana.ConnectorDescriptor, "from_bytes")
    descriptor_names = set(vars(savana.ConnectorDescriptor))
    assert not descriptor_names.intersection(
        {"bytes", "raw", "canonical", "cbor", "base64", "to_bytes"}
    )


@pytest.mark.asyncio
async def test_every_session_business_method_is_async_and_ingest_returns_none():
    for name in SESSION_METHODS:
        assert inspect.iscoroutinefunction(getattr(savana.Session, name)), name

    session = scripted_session()
    assert await session.ingest_text("hello", savana.ContentKind.CHAT_TEXT) is None


@pytest.mark.asyncio
async def test_blocking_rust_work_runs_off_the_event_loop_thread():
    session = transport_session(delay_seconds=0.15)
    event_loop_thread = threading.get_ident()
    close_task = asyncio.create_task(session.close())
    started = time.monotonic()
    await asyncio.sleep(0.02)
    assert time.monotonic() - started < 0.10
    await close_task
    assert savana_core._debug_last_worker_thread(session._inner) != event_loop_thread


@pytest.mark.asyncio
async def test_callback_exception_propagates_once_without_retry():
    session = scripted_session()
    plan = savana_core._debug_plan()
    attempts = 0

    class CallbackBoom(RuntimeError):
        pass

    def approval(request):
        nonlocal attempts
        attempts += 1
        assert isinstance(request, savana.ApprovalRequest)
        raise CallbackBoom("application callback failed")

    with pytest.raises(CallbackBoom, match="application callback failed"):
        await session.execute(plan, approval)
    assert attempts == 1


@pytest.mark.asyncio
async def test_async_context_manager_closes_once_on_success_and_exception():
    successful = transport_session()
    async with successful as entered:
        assert entered is successful
    await asyncio.gather(successful.close(), successful.close())
    assert savana_core._debug_close_count(successful._inner) == 1

    exceptional = transport_session()
    with pytest.raises(ValueError, match="body failed"):
        async with exceptional:
            raise ValueError("body failed")
    assert savana_core._debug_close_count(exceptional._inner) == 1
