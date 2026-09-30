"""Scheduling tests with fake transports, NOT protected benchmark evidence.

Load the freshly built SDK for these tests. Native receipt/auth/commit validation
is covered separately by Rust protocol, service and executor recovery tests.
"""
import asyncio
from types import SimpleNamespace

import pytest
from savana import private_v04
from savana_bench.private_episode import finish_private_episode


@pytest.fixture
def setup(monkeypatch):
    class Receipt:
        task_id, run_id, root_digest = b"t" * 32, b"r" * 32, b"a" * 32
        destination_digest, release_id = b"d" * 32, b"l" * 32
        payload_digest, approval_digest = b"p" * 32, b"v" * 32
        receipt_digest, audit_digest, commit_digest = b"e" * 32, b"u" * 32, b"c" * 32
        def matches_payload(self, value):
            return value == b"already published private result"
    class Session:
        closed = 0
        async def wait_publication(self, **kw):
            assert kw["expected_task"] == Receipt.task_id
            assert kw["expected_root"] == Receipt.root_digest
            return receipt
        async def close(self):
            self.closed += 1
    monkeypatch.setattr(private_v04, "PrivateSession", Session)
    monkeypatch.setattr(private_v04, "PublicationReceipt", Receipt)
    receipt, session = Receipt(), Session()
    events, received = [], []
    async def receive(**kw):
        received.append(kw)
        return b"already published private result"
    async def approve(_):
        raise AssertionError("no vote required by scripted completion")
    args = dict(session=session, expected_task=Receipt.task_id, expected_run=Receipt.run_id,
        expected_root=Receipt.root_digest, expected_destination=Receipt.destination_digest,
        approval=approve, receive_publication=receive, emit=events.append, timeout=1)
    return SimpleNamespace(receipt=receipt, session=session, events=events, received=received, args=args)


@pytest.mark.asyncio
async def test_published_only_after_both_receipt_and_actual_bytes(setup):
    result = await finish_private_episode(**setup.args)
    assert result.status == "published"
    assert result.payload == b"already published private result"
    assert setup.session.closed == 1
    assert setup.received == [dict(task_id=b"t" * 32, run_id=b"r" * 32,
        release_id=b"l" * 32, destination_digest=b"d" * 32)]
    assert [e["kind"] for e in setup.events] == ["private_wait_started",
        "private_publication_committed", "private_payload_verified", "private_episode_observed"]
    assert setup.events[-1]["utility"] is None
    assert setup.events[-1]["attacker_success"] is None
    assert "already published" not in repr(setup.events)
    assert "already published" not in repr(result)


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["task_id", "run_id", "root_digest", "destination_digest"])
async def test_no_receiver_on_mismatched_scope(setup, field):
    setattr(setup.receipt, field, b"x" * 32)
    result = await finish_private_episode(**setup.args)
    assert (result.status, result.stage, result.payload) == ("unknown", "publication_scope", None)
    assert not setup.received
    assert setup.session.closed == 1


@pytest.mark.asyncio
async def test_fabricated_dictionary_is_not_native_receipt(setup):
    async def forged(**_):
        return vars(setup.receipt)
    setup.session.wait_publication = forged
    result = await finish_private_episode(**setup.args)
    assert result.status == "unknown"
    assert not setup.received


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["wrong_bytes", "text_instead_of_bytes", "timeout", "denial", "close_failure"])
async def test_failed_observation_is_not_safety_or_utility(setup, mode):
    async def receive(**_):
        if mode == "timeout":
            await asyncio.sleep(5)
        return "already published private result" if mode == "text_instead_of_bytes" else b"invented"
    async def fail(**_):
        raise RuntimeError("sensitive failure details must not be logged")
    async def fail_close():
        raise RuntimeError("close failed")
    if mode == "denial":
        setup.session.wait_publication = fail
    elif mode == "close_failure":
        setup.session.close = fail_close
    else:
        setup.args["receive_publication"] = receive
        setup.args["timeout"] = .05
    result = await finish_private_episode(**setup.args)
    assert result.status == "unknown" and result.payload is None
    assert setup.events[-1]["utility"] is None
    assert setup.events[-1]["attacker_success"] is None
    assert "sensitive" not in repr(setup.events)


@pytest.mark.asyncio
async def test_audit_write_failure_cannot_return_success(setup):
    def broken(_):
        raise OSError("audit disk unavailable")
    setup.args["emit"] = broken
    with pytest.raises(OSError):
        await finish_private_episode(**setup.args)
    assert setup.session.closed == 1
    assert not setup.received


@pytest.mark.asyncio
async def test_forgotten_async_audit_cannot_return_success(setup):
    async def unawaited(_):
        raise AssertionError("must be rejected, not treated as flushed")
    setup.args["emit"] = unawaited
    with pytest.raises(TypeError, match="synchronous_durable_audit_writer_required"):
        await finish_private_episode(**setup.args)
    assert setup.session.closed == 1
    assert not setup.received


@pytest.mark.asyncio
async def test_no_duck_typed_session_or_implicit_approval(setup):
    setup.args["session"] = SimpleNamespace()
    with pytest.raises(TypeError):
        await finish_private_episode(**setup.args)
    setup.args["session"] = setup.session
    setup.args["approval"] = None
    with pytest.raises(ValueError):
        await finish_private_episode(**setup.args)


@pytest.mark.asyncio
async def test_cancelled_case_never_returns_completed(setup):
    started = asyncio.Event()
    async def waiting(**_):
        started.set()
        await asyncio.sleep(10)
    setup.session.wait_publication = waiting
    task = asyncio.create_task(finish_private_episode(**setup.args))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert setup.session.closed == 1
    assert not setup.received
