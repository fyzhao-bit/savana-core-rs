import asyncio
import base64
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest
from savana.openclaw_bridge.auth import AuthBrokerError, WebAuthnBroker
from savana.openclaw_bridge.protocol import InboundDecoder, ProtocolError
from savana.openclaw_bridge.runtime import (
    ApprovalRouter,
    BridgeProcess,
    BridgeRuntime,
    BridgeRuntimeError,
)


class Choice:
    def __init__(self, value):
        self.value = value


class FakeLimits:
    def __init__(self, max_steps, max_replans, deadline_seconds):
        self.values = (max_steps, max_replans, deadline_seconds)
        self.cancelled = False

    def cancel(self):
        self.cancelled = True


class FakeSdk:
    ContentKind = SimpleNamespace(CHAT_TEXT=Choice("chat_text"))
    IntentPrivacy = SimpleNamespace(PRIVATE=Choice("private"))
    RunLimits = FakeLimits


class FakeHandle:
    kind = "document"

    def __repr__(self):
        return "Handle(<opaque:document>)"


class FakeSession:
    def __init__(self, calls, release_status="succeeded", delay=0):
        self.calls = calls
        self.release_status = release_status
        self.delay = delay
        self.closed = False
        self.active = 0
        self.max_active = 0

    async def _enter(self, name):
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.calls.append(name)
        if self.delay:
            await asyncio.sleep(self.delay)

    def _leave(self):
        self.active -= 1

    async def ingest_text(self, text, content_kind):
        await self._enter(("ingest", text, content_kind.value))
        self._leave()

    async def run_agent(self, privacy, limits, approval, events):
        await self._enter(("run", privacy.value, limits.values))
        await asyncio.to_thread(
            events,
            SimpleNamespace(
                kind="planning", index=None, status=None, purpose=None, count=None
            ),
        )
        self._leave()
        return SimpleNamespace(status="succeeded", outputs=[FakeHandle()])

    async def release(self, handle, approval):
        await self._enter(("release", repr(handle)))
        self._leave()
        return SimpleNamespace(
            status=self.release_status, outputs=[], failure_class=None
        )

    async def close(self):
        self.closed = True
        self.calls.append("close")

    async def list_connectors(self):
        self.calls.append("list_connectors")
        return [SimpleNamespace(name="active-signed")]


class FakeClient:
    def __init__(self, sessions):
        self.sessions = sessions
        self.calls = []

    async def session(self, identity, bootstrap, webauthn, approval):
        self.calls.append(("session", identity, bootstrap, webauthn, approval))
        return self.sessions.pop(0)


class FakeBootstrapSource:
    def __init__(self):
        self.count = 0

    async def next(self):
        self.count += 1
        return f"bootstrap-{self.count}"


class FakeReceiver:
    def __init__(self, payload=b"released response"):
        self.payload = payload
        self.calls = []

    def reserve(self, binding, timeout):
        reservation = object()
        self.calls.append(("reserve", len(binding), timeout, reservation))
        return reservation

    def wait(self, reservation, timeout):
        self.calls.append(("wait", reservation, timeout))
        return self.payload

    def complete(self, reservation):
        self.calls.append(("complete", reservation))

    def clear_failed_no_effect(self, reservation):
        self.calls.append(("clear", reservation))

    def seal_indeterminate(self, reservation):
        self.calls.append(("seal", reservation))

    def close(self):
        self.calls.append(("close",))


async def make_runtime(*, sessions, receiver=None, emit=None, webauthn="webauthn"):
    calls = []
    client = FakeClient(sessions)
    receiver = receiver or FakeReceiver()
    emitted = []

    async def default_emit(message):
        emitted.append(message)

    runtime = BridgeRuntime(
        client=client,
        identity="identity",
        bootstrap_source=FakeBootstrapSource(),
        webauthn=webauthn,
        receiver=receiver,
        sdk=FakeSdk,
        max_steps=8,
        max_replans=2,
        turn_timeout_seconds=2.0,
        approval_timeout_seconds=1.0,
        release_delivery_timeout_seconds=0.25,
        emit=emit or default_emit,
    )
    return runtime, client, receiver, emitted, calls


@pytest.mark.asyncio
async def test_real_turn_shape_reuses_session_and_completes_only_after_emission():
    session_calls = []
    session = FakeSession(session_calls)
    runtime, client, receiver, emitted, _ = await make_runtime(sessions=[session])

    first = await runtime.run_turn(2, "agent", "session", "turn-1", "first request")
    assert first.text == "released response"
    assert not any(call[0] == "complete" for call in receiver.calls)
    await first.complete()
    second = await runtime.run_turn(3, "agent", "session", "turn-2", "second request")
    await second.complete()

    assert len(client.calls) == 1
    assert session_calls == [
        ("ingest", "first request", "chat_text"),
        ("run", "private", (8, 2, 2.0)),
        ("release", "Handle(<opaque:document>)"),
        ("ingest", "second request", "chat_text"),
        ("run", "private", (8, 2, 2.0)),
        ("release", "Handle(<opaque:document>)"),
    ]
    assert all("first request" not in repr(message) for message in emitted)
    assert not hasattr(first, "handle")
    reserve_timeouts = [call[2] for call in receiver.calls if call[0] == "reserve"]
    wait_timeouts = [call[2] for call in receiver.calls if call[0] == "wait"]
    assert reserve_timeouts and wait_timeouts
    assert all(0.25 < timeout <= 2.0 for timeout in reserve_timeouts)
    assert all(0 < timeout <= 0.25 for timeout in wait_timeouts)
    await runtime.shutdown()
    assert session.closed


@pytest.mark.asyncio
async def test_same_session_turns_are_serialized_and_reset_closes_binding():
    first_calls = []
    first_session = FakeSession(first_calls, delay=0.02)
    second_session = FakeSession([])
    runtime, client, _, _, _ = await make_runtime(
        sessions=[first_session, second_session]
    )

    outcomes = await asyncio.gather(
        runtime.run_turn(2, "agent", "session", "turn-1", "one"),
        runtime.run_turn(3, "agent", "session", "turn-2", "two"),
    )
    assert first_session.max_active == 1
    for outcome in outcomes:
        await outcome.complete()
    await runtime.reset_session("agent", "session")
    assert first_session.closed
    replacement = await runtime.run_turn(4, "agent", "session", "turn-3", "three")
    await replacement.complete()
    assert len(client.calls) == 2
    await runtime.shutdown()


@pytest.mark.asyncio
async def test_doctor_uses_fresh_session_and_returns_only_public_readiness():
    session_calls = []
    runtime, _, receiver, _, _ = await make_runtime(
        sessions=[FakeSession(session_calls)]
    )
    receiver.canonical_url = "https://provider.example:43191/savana/final-release"
    result = await runtime.doctor()
    assert result == {
        "active_connector_count": 1,
        "release_target_url": receiver.canonical_url,
        "service_origins": [
            "http://localhost:8768",
            "http://localhost:8767",
            "http://localhost:8766",
        ],
    }
    assert session_calls == ["list_connectors", "close"]
    assert "bootstrap" not in repr(result)
    await runtime.shutdown()


@pytest.mark.asyncio
async def test_failed_no_effect_clears_but_other_release_failures_seal():
    for status, expected_call, expected_code in (
        ("failed_no_effect", "clear", "internal_failure"),
        (
            "effect_succeeded_output_quarantined",
            "seal",
            "indeterminate",
        ),
    ):
        receiver = FakeReceiver()
        runtime, _, receiver, _, _ = await make_runtime(
            sessions=[FakeSession([], release_status=status)], receiver=receiver
        )
        with pytest.raises(BridgeRuntimeError) as failure:
            await runtime.run_turn(2, "agent", "session", "turn", "request")
        assert failure.value.code == expected_code
        assert any(call[0] == expected_call for call in receiver.calls)
        await runtime.shutdown()


@pytest.mark.asyncio
async def test_approval_router_uses_only_trusted_broker_and_cancellation_denies():
    class Broker:
        def __init__(self):
            self.calls = []

        def decide_approval(
            self, display, purpose, deadline_unix_ms, cancel_event=None
        ):
            self.calls.append((display, purpose, deadline_unix_ms, cancel_event))
            return True

    broker = Broker()
    emitted = []

    async def emit(message):
        emitted.append(message)

    router = ApprovalRouter(
        9, broker, emit, asyncio.get_running_loop(), timeout_seconds=1.0
    )
    request = SimpleNamespace(display="Approve exact release", purpose="final_release")
    assert await asyncio.to_thread(router, request) is True
    assert len(broker.calls) == 1
    assert broker.calls[0][0:2] == (request.display, request.purpose)
    assert isinstance(broker.calls[0][3], threading.Event)
    assert emitted == [
        {
            "protocol_version": 1,
            "request_id": 9,
            "type": "turn.event",
            "event": "approval_required",
            "purpose": "final_release",
        }
    ]

    cancelled = ApprovalRouter(
        10, broker, emit, asyncio.get_running_loop(), timeout_seconds=1.0
    )
    cancelled.cancel()
    assert await asyncio.to_thread(cancelled, request) is False
    assert len(broker.calls) == 1


@pytest.mark.asyncio
async def test_approval_router_cancellation_wakes_an_in_flight_broker():
    entered = threading.Event()

    class Broker:
        def decide_approval(
            self, display, purpose, deadline_unix_ms, cancel_event=None
        ):
            assert cancel_event is not None
            entered.set()
            assert cancel_event.wait(timeout=1.0)
            return True

    async def emit(_message):
        return None

    router = ApprovalRouter(
        11, Broker(), emit, asyncio.get_running_loop(), timeout_seconds=2.0
    )
    request = SimpleNamespace(display="Approve exact effect", purpose="tool_execution")
    pending = asyncio.create_task(asyncio.to_thread(router, request))
    assert await asyncio.to_thread(entered.wait, 1.0)
    router.cancel()
    assert await asyncio.wait_for(pending, timeout=0.5) is False


@pytest.mark.asyncio
async def test_every_sdk_approval_callback_uses_broker_and_denial_stops_loop():
    class Broker:
        def __init__(self, decisions):
            self.decisions = iter(decisions)
            self.calls = []

        def decide_approval(
            self, display, purpose, deadline_unix_ms, cancel_event=None
        ):
            self.calls.append((display, purpose, deadline_unix_ms, cancel_event))
            return next(self.decisions)

        def close(self):
            return None

    class ApprovingSession(FakeSession):
        async def run_agent(self, privacy, limits, approval, events):
            self.calls.append("run")
            for index in range(2):
                if not await asyncio.to_thread(
                    approval,
                    SimpleNamespace(
                        display=f"Tool call {index}", purpose="tool_execution"
                    ),
                ):
                    raise BridgeRuntimeError("approval_denied")
            return SimpleNamespace(status="succeeded", outputs=[FakeHandle()])

        async def release(self, handle, approval):
            self.calls.append("release")
            if not await asyncio.to_thread(
                approval,
                SimpleNamespace(display="Release", purpose="final_release"),
            ):
                raise BridgeRuntimeError("approval_denied")
            return SimpleNamespace(status="succeeded", outputs=[], failure_class=None)

    approved_broker = Broker([True, True, True])
    approved_session = ApprovingSession([])
    runtime, _, _, _, _ = await make_runtime(
        sessions=[approved_session], webauthn=approved_broker
    )
    released = await runtime.run_turn(20, "agent", "session", "turn", "request")
    await released.complete()
    assert [call[1] for call in approved_broker.calls] == [
        "tool_execution",
        "tool_execution",
        "final_release",
    ]
    await runtime.shutdown()

    denied_broker = Broker([True, False])
    denied_session = ApprovingSession([])
    runtime, _, _, _, _ = await make_runtime(
        sessions=[denied_session], webauthn=denied_broker
    )
    with pytest.raises(BridgeRuntimeError) as failure:
        await runtime.run_turn(21, "agent", "session", "turn", "request")
    assert failure.value.code == "approval_denied"
    assert denied_session.calls == [("ingest", "request", "chat_text"), "run"]
    assert len(denied_broker.calls) == 2
    await runtime.shutdown()


def test_approval_broker_uses_fresh_correlated_decisions_for_every_call():
    bridge, product = socket.socketpair()
    broker = WebAuthnBroker(bridge.fileno())
    observed = []

    def product_side():
        for expected_decision in (True, True, False):
            length = struct.unpack(">I", product.recv(4))[0]
            request = json.loads(product.recv(length))
            observed.append(request)
            response = json.dumps(
                {
                    "protocol_version": 1,
                    "type": "approval.decision",
                    "approval_id": request["approval_id"],
                    "approved": expected_decision,
                },
                separators=(",", ":"),
            ).encode()
            product.sendall(struct.pack(">I", len(response)) + response)

    thread = threading.Thread(target=product_side)
    thread.start()
    try:
        decisions = [
            broker.decide_approval(
                f"Approve call {index}",
                "tool_execution",
                int(time.time() * 1000) + 5_000,
            )
            for index in range(3)
        ]
        assert decisions == [True, True, False]
        assert len({request["approval_id"] for request in observed}) == 3
        assert all(len(request["approval_id"]) == 43 for request in observed)
        assert all(request["type"] == "approval.decide" for request in observed)
    finally:
        thread.join(timeout=1)
        broker.close()
        bridge.close()
        product.close()


def test_approval_broker_rejects_invalid_requests_and_uncorrelated_responses():
    bridge, product = socket.socketpair()
    broker = WebAuthnBroker(bridge.fileno())
    now = int(time.time() * 1000)
    try:
        for display, purpose, deadline in (
            ("x" * (16 * 1024 + 1), "tool_execution", now + 5_000),
            ("Approve", "unknown", now + 5_000),
            ("Approve", "tool_execution", now - 1),
            ("e\u0301", "tool_execution", now + 5_000),
        ):
            with pytest.raises(AuthBrokerError):
                broker.decide_approval(display, purpose, deadline)

        def product_side():
            length = struct.unpack(">I", product.recv(4))[0]
            request = json.loads(product.recv(length))
            response = json.dumps(
                {
                    "protocol_version": 1,
                    "type": "approval.decision",
                    "approval_id": "A" * 43,
                    "approved": True,
                },
                separators=(",", ":"),
            ).encode()
            assert request["approval_id"] != "A" * 43
            product.sendall(struct.pack(">I", len(response)) + response)

        thread = threading.Thread(target=product_side)
        thread.start()
        with pytest.raises(AuthBrokerError):
            broker.decide_approval("Approve", "tool_execution", now + 5_000)
        thread.join(timeout=1)
    finally:
        broker.close()
        bridge.close()
        product.close()


def test_approval_broker_deadline_covers_lock_wait_and_cancel_wakes_io():
    bridge, product = socket.socketpair()
    broker = WebAuthnBroker(bridge.fileno(), timeout_seconds=2.0)
    cancel_event = threading.Event()
    first_errors = []

    def first_call():
        try:
            broker.decide_approval(
                "Approve first call",
                "tool_execution",
                int(time.time() * 1000) + 2_000,
                cancel_event,
            )
        except AuthBrokerError as error:
            first_errors.append(error)

    thread = threading.Thread(target=first_call)
    thread.start()
    try:
        length = struct.unpack(">I", product.recv(4))[0]
        request = json.loads(product.recv(length))
        assert request["type"] == "approval.decide"

        started = time.monotonic()
        with pytest.raises(AuthBrokerError):
            broker.decide_approval(
                "Approve queued call",
                "tool_execution",
                int(time.time() * 1000) + 150,
            )
        assert time.monotonic() - started < 0.5

        cancel_event.set()
        thread.join(timeout=0.5)
        assert not thread.is_alive()
        assert len(first_errors) == 1
    finally:
        cancel_event.set()
        thread.join(timeout=1)
        broker.close()
        bridge.close()
        product.close()


def test_approval_broker_rejects_a_response_arriving_after_deadline():
    bridge, product = socket.socketpair()
    broker = WebAuthnBroker(bridge.fileno(), timeout_seconds=1.0)

    def product_side():
        try:
            length = struct.unpack(">I", product.recv(4))[0]
            request = json.loads(product.recv(length))
            time.sleep(0.25)
            response = json.dumps(
                {
                    "protocol_version": 1,
                    "type": "approval.decision",
                    "approval_id": request["approval_id"],
                    "approved": True,
                },
                separators=(",", ":"),
            ).encode()
            product.sendall(struct.pack(">I", len(response)) + response)
        except OSError:
            pass

    thread = threading.Thread(target=product_side)
    thread.start()
    try:
        with pytest.raises(AuthBrokerError):
            broker.decide_approval(
                "Approve late response",
                "tool_execution",
                int(time.time() * 1000) + 100,
            )
    finally:
        thread.join(timeout=1)
        broker.close()
        bridge.close()
        product.close()


def test_webauthn_broker_uses_only_bounded_inherited_socket_protocol():
    bridge, product = socket.socketpair()
    broker = WebAuthnBroker(bridge.fileno())

    async def product_side():
        header = await asyncio.to_thread(product.recv, 4)
        length = struct.unpack(">I", header)[0]
        bootstrap_request = json.loads(await asyncio.to_thread(product.recv, length))
        assert bootstrap_request == {
            "protocol_version": 1,
            "type": "session.bootstrap",
        }
        bootstrap_response = json.dumps(
            {
                "protocol_version": 1,
                "type": "session.bootstrap_token",
                "control_plane_token": "fresh-one-use-token",
            },
            separators=(",", ":"),
        ).encode()
        await asyncio.to_thread(
            product.sendall,
            struct.pack(">I", len(bootstrap_response)) + bootstrap_response,
        )

        header = await asyncio.to_thread(product.recv, 4)
        length = struct.unpack(">I", header)[0]
        request = json.loads(await asyncio.to_thread(product.recv, length))
        assert request == {
            "protocol_version": 1,
            "type": "webauthn.assert",
            "options_json": base64.urlsafe_b64encode(b"options").rstrip(b"=").decode(),
        }
        fields = {
            "credential_id": b"credential",
            "authenticator_data": b"authenticator",
            "client_data_json": b"client-data",
            "signature": b"signature",
            "user_handle": b"user",
        }
        response = json.dumps(
            {
                "protocol_version": 1,
                "type": "webauthn.assertion",
                **{
                    key: base64.urlsafe_b64encode(value).rstrip(b"=").decode()
                    for key, value in fields.items()
                },
            },
            separators=(",", ":"),
        ).encode()
        await asyncio.to_thread(
            product.sendall, struct.pack(">I", len(response)) + response
        )
        return fields

    async def scenario():
        product_task = asyncio.create_task(product_side())
        assert await broker.next() == "fresh-one-use-token"
        actual = await asyncio.to_thread(broker.assert_credential, b"options")
        expected = await product_task
        assert actual == expected

    asyncio.run(scenario())
    broker.close()
    bridge.close()
    product.close()

    read_end, write_end = os.pipe()
    try:
        with pytest.raises(AuthBrokerError):
            WebAuthnBroker(read_end)
    finally:
        os.close(read_end)
        os.close(write_end)


@pytest.mark.asyncio
async def test_webauthn_broker_has_its_own_bounded_io_deadline():
    bridge, product = socket.socketpair()
    broker = WebAuthnBroker(bridge.fileno(), timeout_seconds=0.05)
    try:
        with pytest.raises(AuthBrokerError):
            await asyncio.wait_for(broker.next(), timeout=0.5)
    finally:
        broker.close()
        bridge.close()
        product.close()


def test_process_startup_failure_keeps_stdout_protocol_only_and_redacts_stderr():
    completed = subprocess.run(
        [sys.executable, "-m", "savana.openclaw_bridge"],
        capture_output=True,
        timeout=3,
        check=False,
    )
    assert completed.returncode == 2
    assert completed.stdout == b""
    assert completed.stderr == b"savana-openclaw-bridge: startup_failed\n"


@pytest.mark.asyncio
async def test_process_emits_one_terminal_then_completes_durable_delivery():
    order = []

    class Outcome:
        text = "released"

        async def complete(self):
            order.append("complete")

    class Runtime:
        async def run_turn(self, *args):
            order.append(("run", args))
            return Outcome()

        def answer_approval(self, *args):
            return True

        def cancel_turn(self, *args):
            return True

        async def reset_session(self, *args):
            order.append(("reset", args))

        async def shutdown(self):
            order.append("shutdown")

    emitted = []

    async def write(message):
        order.append(("write", message["type"]))
        emitted.append(message)

    process = BridgeProcess(Runtime(), write)
    decoder = InboundDecoder()
    assert await process.handle(
        decoder.decode_line(
            b'{"protocol_version":1,"request_id":1,"type":"initialize","openclaw_version":"2026.7.1-2","plugin_version":"0.1.0"}\n'
        )
    )
    assert await process.handle(
        decoder.decode_line(
            b'{"protocol_version":1,"request_id":2,"type":"turn.start","agent_id":"agent","session_id":"session","turn_id":"turn","text":"request"}\n'
        )
    )
    await process.wait_idle()
    assert [message["type"] for message in emitted] == [
        "initialized",
        "turn.released",
    ]
    assert order[-2:] == [("write", "turn.released"), "complete"]
    assert not hasattr(process, "_terminals")

    assert await process.handle(
        decoder.decode_line(
            b'{"protocol_version":1,"request_id":3,"type":"session.reset","agent_id":"agent","session_id":"session"}\n'
        )
    )
    assert emitted[-1]["type"] == "session.closed"
    assert not await process.handle(
        decoder.decode_line(
            b'{"protocol_version":1,"request_id":4,"type":"shutdown"}\n'
        )
    )


@pytest.mark.asyncio
async def test_doctor_process_rejects_turns_before_any_sdk_effect():
    class Runtime:
        async def shutdown(self):
            return None

    emitted = []

    async def write(message):
        emitted.append(message)

    process = BridgeProcess(Runtime(), write, doctor_only=True)
    decoder = InboundDecoder()
    assert await process.handle(
        decoder.decode_line(
            b'{"protocol_version":1,"request_id":1,"type":"initialize","openclaw_version":"2026.7.1-2","plugin_version":"0.1.0"}\n'
        )
    )
    with pytest.raises(ProtocolError):
        await process.handle(
            decoder.decode_line(
                b'{"protocol_version":1,"request_id":2,"type":"turn.start","agent_id":"agent","session_id":"session","turn_id":"turn","text":"must not run"}\n'
            )
        )
    assert [message["type"] for message in emitted] == ["initialized"]
