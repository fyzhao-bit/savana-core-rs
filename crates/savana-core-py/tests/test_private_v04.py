"""Python scheduling boundary tests. Rust transport/auth tests are separate."""
import asyncio
import threading
from types import SimpleNamespace

import pytest
import savana
import savana_core
from savana import private_v04


class Inner:
    def __init__(self):
        self.closed = 0
        self.calls = []
        self.started = threading.Event()
        self.resume = threading.Event()

    def poll_approval(self):
        self.calls.append("poll")
        return True

    def poll_publication(self):
        self.calls.append("publication")
        return None

    def review_pending(self, approval):
        self.calls.append("review")
        return approval("private display")

    def close(self):
        self.closed += 1


def test_v04_is_separate_and_has_no_agent_execution_or_result_export():
    with pytest.raises(TypeError):
        private_v04.PrivateSession()
    with pytest.raises(TypeError):
        savana_core._PrivateSessionV04()
    with pytest.raises(TypeError):
        private_v04.PublicationReceipt()
    assert set(private_v04.__all__) == {"connect", "connect_from_ingress", "PrivateSession", "PublicationReceipt"}
    assert {n for n in vars(private_v04.PrivateSession) if not n.startswith("_")} == {
        "poll_approval", "poll_publication", "wait_publication", "review_pending", "close",
    }
    assert not hasattr(savana.Session, "private_session_v04")


@pytest.mark.asyncio
async def test_v04_async_approval_runs_on_event_loop_and_close_is_idempotent():
    inner = Inner()
    owner_thread = threading.get_ident()
    async def approval(display):
        assert threading.get_ident() == owner_thread
        assert display == "private display"
        return False
    session = private_v04.PrivateSession._from_core(inner)
    assert "display" not in repr(session)
    async with session:
        assert await session.poll_approval()
        assert not await session.review_pending(approval)
    await session.close()
    assert inner.closed == 1
    with pytest.raises(savana.SavanaError):
        await session.poll_approval()


@pytest.mark.asyncio
async def test_v04_connect_bridges_async_hardware_provider(monkeypatch):
    inner = Inner()
    class Provider:
        async def assert_credential(self, options):
            await asyncio.sleep(0)
            return {"options": options}
    class Client:
        def private_session_v04(self, identity, transfer, provider):
            assert identity == "identity"
            assert transfer == "transfer"
            assert provider.assert_credential(b"options") == {"options": b"options"}
            return inner
    class Identity:
        _inner = "identity"
    monkeypatch.setattr(private_v04._core, "_Client", Client)
    session = await private_v04.connect(identity=Identity(), transfer="transfer", webauthn=Provider())
    await session.close()
    assert inner.closed == 1


@pytest.mark.asyncio
async def test_v04_ingress_calls_dedicated_native_method_without_transfer_export(monkeypatch):
    inner = Inner()
    class Client:
        def private_session_from_ingress_v04(self, identity, ingress_tab, provider):
            assert identity == "identity"
            assert ingress_tab == "authenticated-tab"
            assert provider.assert_credential(b"options") == {"options": b"options"}
            return inner
        def private_session_v04(self, *args):
            raise AssertionError("intermediate transfer must stay in Rust")
    class Identity:
        _inner = "identity"
    class Provider:
        async def assert_credential(self, options):
            return {"options": options}
    monkeypatch.setattr(private_v04._core, "_Client", Client)
    session = await private_v04.connect_from_ingress(identity=Identity(),
        ingress_tab="authenticated-tab", webauthn=Provider())
    await session.close()
    assert inner.closed == 1


@pytest.mark.asyncio
async def test_v04_repeated_cancellation_drains_worker_before_closing():
    inner = Inner()
    def blocking_poll():
        inner.started.set()
        assert inner.resume.wait(5)
        return True
    inner.poll_approval = blocking_poll
    session = private_v04.PrivateSession._from_core(inner)
    task = asyncio.create_task(session.poll_approval())
    assert await asyncio.to_thread(inner.started.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.sleep(0)
    assert inner.closed == 0
    inner.resume.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert inner.closed == 1
    with pytest.raises(savana.SavanaError):
        await session.poll_approval()


@pytest.mark.asyncio
async def test_v04_cancelled_connect_discards_returned_capability(monkeypatch):
    inner = Inner()
    class Client:
        def private_session_v04(self, *args):
            inner.started.set()
            assert inner.resume.wait(5)
            return inner
    class Identity:
        _inner = None
    class Provider:
        def assert_credential(self, options):
            raise AssertionError("unused")
    monkeypatch.setattr(private_v04._core, "_Client", Client)
    task = asyncio.create_task(private_v04.connect(identity=Identity(), transfer="unused", webauthn=Provider()))
    assert await asyncio.to_thread(inner.started.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    inner.resume.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert inner.closed == 1


@pytest.mark.asyncio
async def test_v04_approval_error_is_not_success():
    session = private_v04.PrivateSession._from_core(Inner())
    async def fail(_):
        raise ValueError("synthetic callback failure")
    with pytest.raises(ValueError, match="synthetic callback failure"):
        await session.review_pending(fail)
    await session.close()


TASK, ROOT = bytes([1]) * 32, bytes([2]) * 32


@pytest.mark.asyncio
async def test_v04_wait_needs_publication_not_empty_approval_queue():
    inner = Inner()
    values = iter([None, SimpleNamespace(task_id=TASK, root_digest=ROOT)])
    inner.poll_publication = lambda: next(values)
    inner.poll_approval = lambda: False
    async def never(_):
        raise AssertionError("empty queue is not a vote")
    async with private_v04.PrivateSession._from_core(inner) as session:
        receipt = await session.wait_publication(expected_task=TASK, expected_root=ROOT,
            approval=never, timeout=1, poll_interval=.1)
        assert receipt.task_id == TASK
    assert inner.closed == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["denied", "unknown", "wrong_task", "wrong_root", "callback_error"])
async def test_v04_wait_failure_never_becomes_success(mode):
    inner = Inner()
    async def decision(_):
        if mode == "callback_error":
            raise ValueError("callback failed")
        return False
    expected = savana_core.ApprovalDenied
    if mode == "unknown":
        inner.poll_approval = lambda: False
        expected = TimeoutError
    elif mode.startswith("wrong_"):
        inner.poll_publication = lambda: SimpleNamespace(
            task_id=bytes([3]) * 32 if mode == "wrong_task" else TASK,
            root_digest=bytes([3]) * 32 if mode == "wrong_root" else ROOT)
        expected = savana_core.SavanaError
    elif mode == "callback_error":
        expected = ValueError
    session = private_v04.PrivateSession._from_core(inner)
    with pytest.raises(expected):
        await session.wait_publication(expected_task=TASK, expected_root=ROOT,
            approval=decision, timeout=.15, poll_interval=.1)
    assert inner.closed == 1


@pytest.mark.asyncio
async def test_v04_wait_requires_explicit_bounded_scope():
    inner = Inner()
    session = private_v04.PrivateSession._from_core(inner)
    for override in ({"expected_task": bytes(32)}, {"expected_root": b"bad"},
                     {"timeout": float("nan")}, {"timeout": True},
                     {"poll_interval": 0}, {"approval": None}):
        args = dict(expected_task=TASK, expected_root=ROOT, approval=lambda _: False)
        args.update(override)
        with pytest.raises(ValueError):
            await session.wait_publication(**args)
    assert inner.calls == []
    await session.close()
