"""Async/opaque-owner boundary tests; these are not native deployment evidence."""
import asyncio
import threading

import pytest
import savana_core
from savana import owner_ingress
from savana.private_v04 import PrivateSession


class Inner:
    def __init__(self):
        self.closed = 0
        self.calls = []

    def close(self):
        self.closed += 1

    def task_authorization_context(self):
        self.calls.append("context")
        return "kernel context"

    def commit_text(self, text, approval):
        self.calls.append(("text", text))
        return approval("input approval")

    def approve_task_authorization(self, draft, approval):
        self.calls.append(("draft", draft))
        return approval("task approval")


def test_surface_has_no_files_models_agent_execution_or_raw_capabilities():
    with pytest.raises(TypeError):
        owner_ingress.OwnerIngress()
    with pytest.raises(TypeError):
        savana_core._OwnerIngress()
    assert {n for n in vars(owner_ingress.OwnerIngress) if not n.startswith("_")} == {
        "task_authorization_context", "commit_text", "approve_task_authorization",
        "into_private_session", "close",
    }
    assert set(owner_ingress.__all__) == {"connect", "OwnerIngress"}


@pytest.mark.asyncio
async def test_connect_bridges_existing_passkey_without_identity_or_enrollment(monkeypatch):
    inner = Inner()
    owner_thread = threading.get_ident()

    class Provider:
        async def assert_credential(self, options):
            assert threading.get_ident() == owner_thread
            return options

    class Client:
        def owner_ingress(self, bootstrap, provider):
            assert bootstrap == "kernel-issued"
            assert provider.assert_credential(b"challenge") == b"challenge"
            return inner

    monkeypatch.setattr(owner_ingress._core, "_Client", Client)
    session = await owner_ingress.connect(bootstrap="kernel-issued", webauthn=Provider())
    assert repr(session) == "OwnerIngress(<private-owner>)"
    await session.close()
    await session.close()
    assert inner.closed == 1


@pytest.mark.asyncio
async def test_input_and_root_are_separate_callbacks_on_event_loop():
    inner = Inner()
    session = owner_ingress.OwnerIngress._from_core(inner)
    calls = []
    owner_thread = threading.get_ident()

    async def approve(display):
        assert threading.get_ident() == owner_thread
        calls.append(display)
        return True

    async with session:
        assert await session.task_authorization_context() == "kernel context"
        await session.commit_text("synthetic 测试", approve)
        assert calls == ["input approval"]
        await session.approve_task_authorization("typed draft", approve)
        assert calls == ["input approval", "task approval"]
    assert inner.closed == 1
    with pytest.raises(savana_core.SavanaError):
        await session.task_authorization_context()


@pytest.mark.asyncio
async def test_input_limit_uses_utf8_bytes_before_native_io():
    inner = Inner()
    session = owner_ingress.OwnerIngress._from_core(inner)
    for text in ["", b"bytes", "x" * 65537, "字" * 21846]:
        with pytest.raises(ValueError):
            await session.commit_text(text, lambda _: True)
    assert inner.calls == []
    await session.commit_text("字" * 21845, lambda _: True)
    await session.close()


@pytest.mark.asyncio
async def test_uncertain_response_closes_without_retry():
    inner = Inner()

    def fail(text, callback):
        inner.calls.append("one attempt")
        raise RuntimeError("connection lost")

    inner.commit_text = fail
    session = owner_ingress.OwnerIngress._from_core(inner)
    with pytest.raises(RuntimeError):
        await session.commit_text("synthetic", lambda _: True)
    with pytest.raises(savana_core.SavanaError):
        await session.commit_text("synthetic", lambda _: True)
    assert inner.calls == ["one attempt"]
    assert inner.closed == 1


@pytest.mark.asyncio
async def test_private_handoff_is_one_way_without_intermediate_token():
    inner, private = Inner(), Inner()
    inner.into_private_session = lambda: private
    session = owner_ingress.OwnerIngress._from_core(inner)
    result = await session.into_private_session()
    assert isinstance(result, PrivateSession)
    with pytest.raises(savana_core.SavanaError):
        await session.into_private_session()
    await result.close()
    assert private.closed == 1


@pytest.mark.asyncio
async def test_cancelled_handoff_drains_worker_and_closes_both_capabilities():
    inner, private = Inner(), Inner()
    started, finish = threading.Event(), threading.Event()

    def handoff():
        started.set()
        assert finish.wait(5)
        return private

    inner.into_private_session = handoff
    session = owner_ingress.OwnerIngress._from_core(inner)
    task = asyncio.create_task(session.into_private_session())
    assert await asyncio.to_thread(started.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    finish.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert private.closed == 1
    assert inner.closed == 1
    with pytest.raises(savana_core.SavanaError):
        await session.task_authorization_context()


@pytest.mark.asyncio
async def test_cancelled_login_does_not_orphan_authenticated_owner(monkeypatch):
    inner = Inner()
    started, finish = threading.Event(), threading.Event()

    class Provider:
        def assert_credential(self, options):
            return options

    class Client:
        def owner_ingress(self, *args):
            started.set()
            assert finish.wait(5)
            return inner

    monkeypatch.setattr(owner_ingress._core, "_Client", Client)
    task = asyncio.create_task(owner_ingress.connect(bootstrap="issued", webauthn=Provider()))
    assert await asyncio.to_thread(started.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    finish.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert inner.closed == 1
