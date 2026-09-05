import asyncio
import inspect
import subprocess
import sys
import threading
import textwrap
import time

import pytest

import savana
import savana_core


CORE_TYPES = {
    "Identity",
    "Client",
    "Session",
    "TaskAuthorizationDraft",
    "TaskAuthorizationReceipt",
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
    "establish_task_authorization",
    "approve_task_authorization",
    "revoke_task_authorization",
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

# These are value construction/control helpers, not Identity/Client/Session
# business workflows, so they are inventoried separately from the 18 workflows.
SUPPORTING_VALUE_METHODS = {
    savana.ConnectorDescriptor: {"load"},
    savana.RunLimits: {"cancel"},
    savana.TaskAuthorizationDraft: {"from_canonical_bytes"},
}


def public_methods(cls):
    return {
        name
        for name in vars(cls)
        if not name.startswith("_") and callable(getattr(cls, name))
    }


def test_task_authorization_data_cannot_construct_authority_or_bypass_validation():
    for malformed in (b"", b"\x80", b"\x81\x01", b"\x9f\xff"):
        with pytest.raises(savana.SavanaError):
            savana.TaskAuthorizationDraft.from_canonical_bytes(malformed)
    with pytest.raises(TypeError):
        savana.TaskAuthorizationReceipt()
    assert not hasattr(savana.TaskAuthorizationDraft, "sign")
    assert not hasattr(savana.TaskAuthorizationReceipt, "authorize")


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
    assert 1 + 2 + len(SESSION_METHODS) == 18
    for value_type, methods in SUPPORTING_VALUE_METHODS.items():
        assert public_methods(value_type) == methods
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
    assert list(inspect.signature(savana.Session.read_view).parameters) == [
        "self",
        "handle",
    ]
    assert list(inspect.signature(savana.Client.session).parameters) == [
        "self",
        "identity",
        "bootstrap",
        "webauthn",
        "approval",
    ]


def test_release_receiver_is_native_private_infrastructure_not_public_sdk():
    assert hasattr(savana_core, "_ReleaseReceiver")
    assert not hasattr(savana, "_ReleaseReceiver")
    assert "_ReleaseReceiver" not in savana.__all__


def test_choices_and_exception_inheritance_are_stable():
    assert savana.IntentPrivacy.PRIVATE.value == "private"
    assert savana.IntentPrivacy.THIRD_PARTY.value == "third_party"
    assert savana.ContentKind.CHAT_TEXT.value == "chat_text"
    assert savana.ContentKind.PLAIN_TEXT.value == "plain_text"
    assert savana.ContentKind.PARSED_DOCUMENT.value == "parsed_document"
    assert issubclass(savana.AuthError, savana.SavanaError)
    assert issubclass(savana.ApprovalDenied, savana.SavanaError)
    assert issubclass(savana.PolicyRefused, savana.SavanaError)

    limits = savana.RunLimits(2, 1, 1.0)
    assert limits.cancelled is False
    limits.cancel()
    assert limits.cancelled is True


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
    with pytest.raises(TypeError):
        savana.ConnectorDescriptor(b"editable descriptor bytes")
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
async def test_masked_view_projects_only_an_opaque_continuation_handle():
    session = savana.Session._from_core(savana_core._debug_view_session())

    first = await session.read_view(session.initial_document)
    assert first.variant == "document_page"
    assert first.page_index == 0
    assert first.text == "first"
    assert isinstance(first.continuation, savana.Handle)
    assert first.continuation.kind == "view-cursor"
    assert repr(first.continuation) == "Handle(<opaque:view-cursor>)"
    for forbidden in ("bytes", "raw", "canonical", "cbor", "base64", "to_bytes"):
        assert not hasattr(first.continuation, forbidden)

    second = await session.read_view(first.continuation)
    assert second.variant == "document_page"
    assert second.page_index == 1
    assert second.text == "second"
    assert second.continuation is None
    await session.close()


@pytest.mark.asyncio
async def test_structured_masked_view_exposes_immutable_public_fields_only():
    session = savana.Session._from_core(savana_core._debug_structured_view_session())
    view = await session.read_view(session.initial_document)

    assert view.variant == "structured"
    assert view.template_id == 7
    assert view.field_count == 1
    assert view.fields == (
        (
            "recipient",
            "Send to {{PERSON_0}}",
            ((0, "{{PERSON_0}}", "personal_data"),),
        ),
    )
    assert isinstance(view.fields, tuple)
    assert isinstance(view.fields[0], tuple)
    for forbidden in ("raw", "private", "capability", "canonical", "cbor", "to_bytes"):
        assert not hasattr(view, forbidden)
    await session.close()


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


def test_callback_reentrancy_fails_promptly_once_and_session_can_close():
    # Run the regression in a child process so a blocking-lock mutation fails by
    # timeout without wedging the pytest interpreter itself.
    script = textwrap.dedent(
        """
        import asyncio
        import time

        import savana
        import savana_core


        async def main():
            approval_session = savana.Session._from_core(
                savana_core._debug_scripted_session()
            )
            approval_attempts = 0
            approval_error = None
            operation_error = None

            def approval(_request):
                nonlocal approval_attempts, approval_error, operation_error
                approval_attempts += 1
                try:
                    approval_session.initial_document
                except savana.SavanaError as error:
                    approval_error = error
                else:
                    raise AssertionError("reentrant property access succeeded")

                try:
                    asyncio.run(approval_session.list_connectors())
                except savana.SavanaError as error:
                    operation_error = error
                else:
                    raise AssertionError("reentrant session operation succeeded")
                raise approval_error

            started = time.monotonic()
            try:
                await asyncio.wait_for(
                    approval_session.execute(savana_core._debug_plan(), approval),
                    timeout=0.75,
                )
            except savana.SavanaError as outer_error:
                assert outer_error is approval_error
                assert outer_error.code == "invalid_state"
            else:
                raise AssertionError("approval callback unexpectedly succeeded")
            assert time.monotonic() - started < 0.75
            assert operation_error.code == "invalid_state"
            assert approval_attempts == 1
            await asyncio.wait_for(approval_session.close(), timeout=0.75)
            assert savana_core._debug_close_count(approval_session._inner) == 1

            event_session = savana.Session._from_core(
                savana_core._debug_scripted_session()
            )
            event_attempts = 0
            event_error = None

            def events(_event):
                nonlocal event_attempts, event_error
                event_attempts += 1
                try:
                    event_session.initial_document
                except savana.SavanaError as error:
                    event_error = error
                    raise
                raise AssertionError("reentrant event property access succeeded")

            started = time.monotonic()
            try:
                await asyncio.wait_for(
                    event_session.run_agent(
                        savana.IntentPrivacy.PRIVATE,
                        savana.RunLimits(2, 1, 1.0),
                        lambda _request: True,
                        events,
                    ),
                    timeout=0.75,
                )
            except savana.SavanaError as outer_error:
                assert outer_error is event_error
                assert outer_error.code == "invalid_state"
            else:
                raise AssertionError("event callback unexpectedly succeeded")
            assert time.monotonic() - started < 0.75
            assert event_attempts == 1
            await asyncio.wait_for(event_session.close(), timeout=0.75)
            assert savana_core._debug_close_count(event_session._inner) == 1


        asyncio.run(main())
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=3.0,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_callback_failures_are_operation_scoped_inside_the_extension():
    assert savana_core._debug_callback_error_isolation() == (
        "unrelated",
        True,
        True,
        True,
    )


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
