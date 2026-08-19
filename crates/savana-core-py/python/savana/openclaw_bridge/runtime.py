"""Savana-owned session and turn orchestration for the OpenClaw bridge."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import sys
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .auth import WebAuthnBroker
from .config import BridgeConfig, ConfigError
from .protocol import (
    BRIDGE_VERSION,
    MAX_LINE_BYTES,
    PROTOCOL_VERSION,
    InboundDecoder,
    InboundMessage,
    ProtocolError,
    encode_outbound,
)

Emit = Callable[[dict[str, Any]], Awaitable[None]]
SERVICE_ORIGINS = (
    "http://localhost:8768",
    "http://localhost:8767",
    "http://localhost:8766",
)


class BridgeRuntimeError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(f"{code}: Savana turn failed")
        self.code = code


@dataclass(slots=True)
class _PendingApproval:
    event: threading.Event
    approved: bool = False


class ApprovalRouter:
    """Turns synchronous SDK approval callbacks into correlated bridge events."""

    def __init__(
        self,
        turn_request_id: int,
        emit: Emit,
        loop: asyncio.AbstractEventLoop,
        *,
        timeout_seconds: float,
        absolute_deadline: float | None = None,
    ) -> None:
        self._turn_request_id = turn_request_id
        self._emit = emit
        self._loop = loop
        self._timeout_seconds = timeout_seconds
        self._absolute_deadline = absolute_deadline
        self._pending: dict[str, _PendingApproval] = {}
        self._lock = threading.Lock()
        self._cancelled = False

    def __call__(self, request: Any) -> bool:
        display = getattr(request, "display", None)
        purpose = getattr(request, "purpose", None)
        if not isinstance(display, str) or not isinstance(purpose, str):
            return False
        approval_id = secrets.token_urlsafe(32)
        pending = _PendingApproval(threading.Event())
        with self._lock:
            if self._cancelled or self._pending:
                return False
            self._pending[approval_id] = pending
        timeout_seconds = self._timeout_seconds
        if self._absolute_deadline is not None:
            timeout_seconds = min(
                timeout_seconds,
                max(0.0, self._absolute_deadline - time.monotonic()),
            )
        if timeout_seconds <= 0:
            with self._lock:
                self._pending.pop(approval_id, None)
            return False
        approval_deadline = time.monotonic() + timeout_seconds
        deadline_unix_ms = int((time.time() + timeout_seconds) * 1000)
        future = asyncio.run_coroutine_threadsafe(
            self._emit(
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "request_id": self._turn_request_id,
                    "type": "approval.request",
                    "approval_id": approval_id,
                    "display": display,
                    "purpose": purpose,
                    "deadline_unix_ms": deadline_unix_ms,
                }
            ),
            self._loop,
        )
        try:
            future.result(timeout=timeout_seconds)
        except Exception:  # noqa: BLE001 - any output failure denies approval.
            with self._lock:
                self._pending.pop(approval_id, None)
            return False
        signalled = pending.event.wait(
            max(0.0, approval_deadline - time.monotonic())
        )
        with self._lock:
            self._pending.pop(approval_id, None)
            return signalled and pending.approved and not self._cancelled

    def answer(self, turn_request_id: int, approval_id: str, approved: bool) -> bool:
        with self._lock:
            if turn_request_id != self._turn_request_id or self._cancelled:
                return False
            pending = self._pending.get(approval_id)
            if pending is None or pending.event.is_set():
                return False
            pending.approved = approved is True
            pending.event.set()
            return True

    def cancel(self) -> None:
        with self._lock:
            self._cancelled = True
            for pending in self._pending.values():
                pending.approved = False
                pending.event.set()


class _SessionApprovalDispatcher:
    def __init__(self) -> None:
        self._router: ApprovalRouter | None = None
        self._lock = threading.Lock()

    def bind(self, router: ApprovalRouter) -> None:
        with self._lock:
            if self._router is not None:
                raise BridgeRuntimeError("internal_failure")
            self._router = router

    def clear(self, router: ApprovalRouter) -> None:
        with self._lock:
            if self._router is router:
                self._router = None

    def __call__(self, request: Any) -> bool:
        with self._lock:
            router = self._router
        return False if router is None else router(request)


@dataclass(slots=True)
class _SessionRecord:
    session: Any
    approvals: _SessionApprovalDispatcher
    lock: asyncio.Lock


@dataclass(slots=True)
class _ActiveTurn:
    key: tuple[str, str]
    limits: Any
    approvals: ApprovalRouter


class ReleasedTurn:
    __slots__ = ("_completed", "_lock", "_receiver", "_reservation", "text")

    def __init__(self, text: str, receiver: Any, reservation: Any) -> None:
        self.text = text
        self._receiver = receiver
        self._reservation = reservation
        self._lock = asyncio.Lock()
        self._completed = False

    async def complete(self) -> None:
        async with self._lock:
            if self._completed:
                return
            await asyncio.to_thread(self._receiver.complete, self._reservation)
            self._completed = True


class BridgeRuntime:
    def __init__(
        self,
        *,
        client: Any,
        identity: Any,
        bootstrap_source: Any,
        webauthn: Any,
        receiver: Any,
        sdk: Any,
        max_steps: int,
        max_replans: int,
        turn_timeout_seconds: float,
        approval_timeout_seconds: float,
        release_delivery_timeout_seconds: float,
        emit: Emit,
    ) -> None:
        self._client = client
        self._identity = identity
        self._bootstrap_source = bootstrap_source
        self._webauthn = webauthn
        self._receiver = receiver
        self._sdk = sdk
        self._max_steps = max_steps
        self._max_replans = max_replans
        self._turn_timeout_seconds = turn_timeout_seconds
        self._approval_timeout_seconds = approval_timeout_seconds
        self._release_delivery_timeout_seconds = release_delivery_timeout_seconds
        self._emit = emit
        self._sessions: dict[tuple[str, str], _SessionRecord] = {}
        self._sessions_lock = asyncio.Lock()
        self._active: dict[int, _ActiveTurn] = {}
        self._active_lock = asyncio.Lock()
        self._instance_binding = secrets.token_bytes(32)
        self._closed = False

    async def run_turn(
        self,
        request_id: int,
        agent_id: str,
        session_id: str,
        turn_id: str,
        text: str,
    ) -> ReleasedTurn:
        if self._closed:
            raise BridgeRuntimeError("internal_failure")
        loop = asyncio.get_running_loop()
        turn_deadline = time.monotonic() + self._turn_timeout_seconds
        approvals = ApprovalRouter(
            request_id,
            self._emit,
            loop,
            timeout_seconds=self._approval_timeout_seconds,
            absolute_deadline=turn_deadline,
        )
        limits = self._sdk.RunLimits(
            self._max_steps,
            self._max_replans,
            self._turn_timeout_seconds,
        )
        key = (agent_id, session_id)
        active = _ActiveTurn(key, limits, approvals)
        async with self._active_lock:
            if request_id in self._active:
                raise BridgeRuntimeError("protocol_failure")
            self._active[request_id] = active
        reservation = None
        try:
            async with asyncio.timeout(self._turn_timeout_seconds):
                record = await self._session(key, approvals)
                async with record.lock:
                    if limits.cancelled:
                        raise BridgeRuntimeError("cancelled")
                    record.approvals.bind(approvals)
                    try:
                        await record.session.ingest_text(
                            text, self._sdk.ContentKind.CHAT_TEXT
                        )
                        result = await record.session.run_agent(
                            self._sdk.IntentPrivacy.PRIVATE,
                            limits,
                            approvals,
                            self._event_callback(request_id, loop),
                        )
                        document = self._select_document(result)
                        turn_binding = self._turn_binding(
                            request_id, agent_id, session_id, turn_id
                        )
                        reservation_timeout = self._remaining_turn_timeout(
                            turn_deadline
                        )
                        reservation = await asyncio.to_thread(
                            self._receiver.reserve,
                            turn_binding,
                            reservation_timeout,
                        )
                        release = await record.session.release(document, approvals)
                        if release.status == "failed_no_effect":
                            await asyncio.to_thread(
                                self._receiver.clear_failed_no_effect, reservation
                            )
                            reservation = None
                            raise BridgeRuntimeError("internal_failure")
                        if release.status != "succeeded":
                            await asyncio.to_thread(
                                self._receiver.seal_indeterminate, reservation
                            )
                            reservation = None
                            raise BridgeRuntimeError("indeterminate")
                        payload = await asyncio.to_thread(
                            self._receiver.wait,
                            reservation,
                            self._remaining_release_timeout(turn_deadline),
                        )
                        try:
                            released_text = bytes(payload).decode(
                                "utf-8", errors="strict"
                            )
                        except (TypeError, UnicodeDecodeError) as error:
                            raise BridgeRuntimeError("protocol_failure") from error
                        if not released_text or "\x00" in released_text:
                            raise BridgeRuntimeError("protocol_failure")
                        return ReleasedTurn(released_text, self._receiver, reservation)
                    finally:
                        record.approvals.clear(approvals)
        except TimeoutError as error:
            limits.cancel()
            approvals.cancel()
            if reservation is not None:
                await self._seal(reservation)
            raise BridgeRuntimeError("deadline_exceeded") from error
        except asyncio.CancelledError as error:
            limits.cancel()
            approvals.cancel()
            if reservation is not None:
                await self._seal(reservation)
            raise BridgeRuntimeError("cancelled") from error
        except BridgeRuntimeError:
            if reservation is not None:
                await self._seal(reservation)
            raise
        except Exception as error:
            if reservation is not None:
                await self._seal(reservation)
            raise BridgeRuntimeError(_stable_error_code(error)) from error
        finally:
            async with self._active_lock:
                self._active.pop(request_id, None)

    def answer_approval(
        self,
        turn_request_id: int,
        approval_id: str,
        approved: bool,
    ) -> bool:
        active = self._active.get(turn_request_id)
        return (
            False
            if active is None
            else active.approvals.answer(turn_request_id, approval_id, approved)
        )

    def cancel_turn(self, turn_request_id: int) -> bool:
        active = self._active.get(turn_request_id)
        if active is None:
            return False
        active.limits.cancel()
        active.approvals.cancel()
        return True

    async def reset_session(self, agent_id: str, session_id: str) -> None:
        key = (agent_id, session_id)
        for active in tuple(self._active.values()):
            if active.key == key:
                active.limits.cancel()
                active.approvals.cancel()
        async with self._sessions_lock:
            record = self._sessions.pop(key, None)
        if record is not None:
            async with record.lock:
                await record.session.close()

    async def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        for active in tuple(self._active.values()):
            active.limits.cancel()
            active.approvals.cancel()
        async with self._sessions_lock:
            records = tuple(self._sessions.values())
            self._sessions.clear()
        for record in records:
            async with record.lock:
                try:
                    await record.session.close()
                except Exception:  # noqa: BLE001,S112 - shutdown is best effort and redacted.
                    continue
        await asyncio.to_thread(self._receiver.close)
        close = getattr(self._webauthn, "close", None)
        if callable(close):
            await asyncio.to_thread(close)

    async def doctor(self) -> dict[str, Any]:
        """Return only bounded, public deployment readiness evidence."""
        if self._closed:
            raise BridgeRuntimeError("internal_failure")
        session = None
        try:
            async with asyncio.timeout(self._turn_timeout_seconds):
                bootstrap = await self._bootstrap_source.next()
                session = await self._client.session(
                    self._identity,
                    bootstrap,
                    self._webauthn,
                    lambda _request: False,
                )
                connectors = await session.list_connectors()
                if not isinstance(connectors, (list, tuple)) or len(connectors) > 0xFFFFFFFF:
                    raise BridgeRuntimeError("protocol_failure")
                return {
                    "active_connector_count": len(connectors),
                    "release_target_url": self._receiver.canonical_url,
                    "service_origins": list(SERVICE_ORIGINS),
                }
        except TimeoutError as error:
            raise BridgeRuntimeError("deadline_exceeded") from error
        except BridgeRuntimeError:
            raise
        except Exception as error:
            raise BridgeRuntimeError(_stable_error_code(error)) from error
        finally:
            if session is not None:
                try:
                    await session.close()
                except Exception:  # noqa: BLE001 - doctor remains redacted.
                    pass

    async def _session(
        self,
        key: tuple[str, str],
        approvals: ApprovalRouter,
    ) -> _SessionRecord:
        async with self._sessions_lock:
            existing = self._sessions.get(key)
            if existing is not None:
                return existing
            dispatcher = _SessionApprovalDispatcher()
            dispatcher.bind(approvals)
            try:
                bootstrap = await self._bootstrap_source.next()
                session = await self._client.session(
                    self._identity,
                    bootstrap,
                    self._webauthn,
                    dispatcher,
                )
            finally:
                dispatcher.clear(approvals)
            record = _SessionRecord(session, dispatcher, asyncio.Lock())
            self._sessions[key] = record
            return record

    def _select_document(self, result: Any) -> Any:
        if getattr(result, "status", None) != "succeeded":
            if getattr(result, "status", None) == "effect_succeeded_output_quarantined":
                raise BridgeRuntimeError("indeterminate")
            raise BridgeRuntimeError("no_output")
        outputs = getattr(result, "outputs", None)
        if not isinstance(outputs, list) or len(outputs) != 1:
            raise BridgeRuntimeError("no_output")
        document = outputs[0]
        if getattr(document, "kind", None) != "document":
            raise BridgeRuntimeError("no_output")
        return document

    def _event_callback(
        self,
        request_id: int,
        loop: asyncio.AbstractEventLoop,
    ) -> Callable[[Any], None]:
        def callback(event: Any) -> None:
            kind = getattr(event, "kind", None)
            message: dict[str, Any] = {
                "protocol_version": PROTOCOL_VERSION,
                "request_id": request_id,
                "type": "turn.event",
                "event": kind,
            }
            for field in ("index", "status", "purpose", "count"):
                value = getattr(event, field, None)
                if value is not None:
                    message[field] = value
            future = asyncio.run_coroutine_threadsafe(self._emit(message), loop)
            future.result(timeout=self._turn_timeout_seconds)

        return callback

    def _turn_binding(
        self,
        request_id: int,
        agent_id: str,
        session_id: str,
        turn_id: str,
    ) -> bytes:
        hasher = hashlib.sha256()
        hasher.update(b"SAVANA_OPENCLAW_TURN_BINDING_V1\0")
        hasher.update(self._instance_binding)
        hasher.update(request_id.to_bytes(8, "big"))
        for value in (agent_id, session_id, turn_id):
            encoded = value.encode("utf-8", errors="strict")
            hasher.update(len(encoded).to_bytes(4, "big"))
            hasher.update(encoded)
        return hasher.digest()

    async def _seal(self, reservation: Any) -> None:
        try:
            await asyncio.to_thread(self._receiver.seal_indeterminate, reservation)
        except Exception:  # noqa: BLE001 - the original failure remains authoritative.
            return

    def _remaining_release_timeout(self, turn_deadline: float) -> float:
        return min(
            self._release_delivery_timeout_seconds,
            self._remaining_turn_timeout(turn_deadline),
        )

    @staticmethod
    def _remaining_turn_timeout(turn_deadline: float) -> float:
        remaining = turn_deadline - time.monotonic()
        if remaining <= 0:
            raise BridgeRuntimeError("deadline_exceeded")
        return remaining


def _stable_error_code(error: Exception) -> str:
    code = getattr(error, "code", None)
    if code in {"authentication_failed", "invalid_bootstrap"}:
        return "authentication_failed"
    if code == "approval_denied":
        return "approval_denied"
    if code == "policy_refused":
        return "policy_refused"
    if code in {"deadline_exceeded", "release_deadline"}:
        return "deadline_exceeded"
    if code in {"release_sealed", "release_already_claimed"}:
        return "indeterminate"
    return "internal_failure"


class BridgeProcess:
    """Closed protocol dispatcher around one :class:`BridgeRuntime`."""

    def __init__(
        self, runtime: BridgeRuntime, write: Emit, *, doctor_only: bool = False
    ) -> None:
        self._runtime = runtime
        self._write = write
        self._decoder = InboundDecoder()
        self._turns: dict[int, tuple[tuple[str, str], asyncio.Task[None]]] = {}
        self._initialized = False
        self._shutting_down = False
        self._doctor_only = doctor_only

    async def handle_line(self, line: bytes) -> bool:
        message = self._decoder.decode_line(line)
        return await self.handle(message)

    async def handle(self, message: InboundMessage) -> bool:
        payload = message.payload
        if message.type == "initialize":
            self._initialized = True
            await self._write(
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "request_id": message.request_id,
                    "type": "initialized",
                    "bridge_version": BRIDGE_VERSION,
                }
            )
            return True
        if not self._initialized:
            raise ProtocolError("bridge is not initialized")
        if self._doctor_only and message.type not in {"doctor.request", "shutdown"}:
            raise ProtocolError("doctor bridge accepts only readiness requests")
        if message.type == "turn.start":
            if message.request_id in self._turns:
                raise ProtocolError("duplicate bridge turn")
            key = (payload["agent_id"], payload["session_id"])
            task = asyncio.create_task(
                self._run_turn(
                    message.request_id,
                    payload["agent_id"],
                    payload["session_id"],
                    payload["turn_id"],
                    payload["text"],
                )
            )
            self._turns[message.request_id] = (key, task)
            return True
        if message.type == "approval.answer":
            if not self._runtime.answer_approval(
                payload["turn_request_id"],
                payload["approval_id"],
                payload["approved"],
            ):
                raise ProtocolError("approval answer is stale or mismatched")
            return True
        if message.type == "turn.cancel":
            if not self._runtime.cancel_turn(payload["turn_request_id"]):
                raise ProtocolError("turn cancellation is stale or mismatched")
            turn = self._turns.get(payload["turn_request_id"])
            if turn is not None:
                turn[1].cancel()
            return True
        if message.type == "session.reset":
            await self._cancel_session((payload["agent_id"], payload["session_id"]))
            await self._runtime.reset_session(
                payload["agent_id"], payload["session_id"]
            )
            await self._write(
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "request_id": message.request_id,
                    "type": "session.closed",
                }
            )
            return True
        if message.type == "doctor.request":
            try:
                result = await self._runtime.doctor()
                await self._write(
                    {
                        "protocol_version": PROTOCOL_VERSION,
                        "request_id": message.request_id,
                        "type": "doctor.result",
                        **result,
                    }
                )
            except BridgeRuntimeError as error:
                await self._write(
                    {
                        "protocol_version": PROTOCOL_VERSION,
                        "request_id": message.request_id,
                        "type": "doctor.failed",
                        "code": error.code,
                    }
                )
            return True
        if message.type == "shutdown":
            self._shutting_down = True
            await self._cancel_all()
            await self._runtime.shutdown()
            return False
        raise ProtocolError("unsupported bridge message")

    async def wait_idle(self) -> None:
        tasks = tuple(task for _, task in self._turns.values())
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _run_turn(
        self,
        request_id: int,
        agent_id: str,
        session_id: str,
        turn_id: str,
        text: str,
    ) -> None:
        terminal_emitted = False
        try:
            outcome = await self._runtime.run_turn(
                request_id, agent_id, session_id, turn_id, text
            )
            if self._shutting_down:
                return
            await self._terminal(
                {
                    "protocol_version": PROTOCOL_VERSION,
                    "request_id": request_id,
                    "type": "turn.released",
                    "text": outcome.text,
                }
            )
            terminal_emitted = True
            await outcome.complete()
        except BridgeRuntimeError as error:
            if not self._shutting_down and not terminal_emitted:
                await self._terminal(
                    {
                        "protocol_version": PROTOCOL_VERSION,
                        "request_id": request_id,
                        "type": "turn.failed",
                        "code": error.code,
                    }
                )
        except asyncio.CancelledError:
            if not self._shutting_down and not terminal_emitted:
                await self._terminal(
                    {
                        "protocol_version": PROTOCOL_VERSION,
                        "request_id": request_id,
                        "type": "turn.failed",
                        "code": "cancelled",
                    }
                )
        except Exception:  # noqa: BLE001 - process boundary maps every error to a stable code.
            if not self._shutting_down and not terminal_emitted:
                await self._terminal(
                    {
                        "protocol_version": PROTOCOL_VERSION,
                        "request_id": request_id,
                        "type": "turn.failed",
                        "code": "internal_failure",
                    }
                )
        finally:
            self._turns.pop(request_id, None)

    async def _terminal(self, message: dict[str, Any]) -> None:
        await self._write(message)

    async def _cancel_session(self, key: tuple[str, str]) -> None:
        tasks = []
        for request_id, (turn_key, task) in tuple(self._turns.items()):
            if turn_key == key:
                self._runtime.cancel_turn(request_id)
                task.cancel()
                tasks.append(task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _cancel_all(self) -> None:
        tasks = []
        for request_id, (_, task) in tuple(self._turns.items()):
            self._runtime.cancel_turn(request_id)
            task.cancel()
            tasks.append(task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


class _StdoutWriter:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def __call__(self, message: dict[str, Any]) -> None:
        encoded = encode_outbound(message)
        async with self._lock:
            await asyncio.to_thread(self._write, encoded)

    @staticmethod
    def _write(encoded: bytes) -> None:
        sys.stdout.buffer.write(encoded)
        sys.stdout.buffer.flush()


class _DoctorReceiverInfo:
    def __init__(self, canonical_url: str) -> None:
        self.canonical_url = canonical_url

    def close(self) -> None:
        return None


async def _run_stdio(config: BridgeConfig, *, doctor_only: bool) -> int:
    import savana

    try:
        expected_client_pin = await asyncio.to_thread(
            _read_exact_private, config.expected_client_spki_pin_path, 32
        )
        if doctor_only:
            receiver = _DoctorReceiverInfo(
                "https://"
                f"{config.release_canonical_host}:{config.release_listen_port}"
                "/savana/final-release"
            )
        else:
            import savana_core

            receiver = savana_core._ReleaseReceiver(
                str(config.release_journal_path),
                config.release_canonical_host,
                config.release_listen_port,
                str(config.client_root_certificate_path),
                str(config.server_certificate_path),
                str(config.server_private_key_path),
                expected_client_pin,
            )
        webauthn = WebAuthnBroker(
            config.webauthn_fd,
            timeout_seconds=config.turn_timeout_seconds,
        )
        identity = savana.Identity.load(config.identity_path)
        writer = _StdoutWriter()
        runtime = BridgeRuntime(
            client=savana.Client(),
            identity=identity,
            bootstrap_source=webauthn,
            webauthn=webauthn,
            receiver=receiver,
            sdk=savana,
            max_steps=config.max_steps,
            max_replans=config.max_replans,
            turn_timeout_seconds=config.turn_timeout_seconds,
            approval_timeout_seconds=config.approval_timeout_seconds,
            release_delivery_timeout_seconds=config.release_delivery_timeout_seconds,
            emit=writer,
        )
    except Exception:  # noqa: BLE001 - startup exposes only a redacted category.
        return 2
    process = BridgeProcess(runtime, writer, doctor_only=doctor_only)
    try:
        while True:
            line = await asyncio.to_thread(
                sys.stdin.buffer.readline, MAX_LINE_BYTES + 1
            )
            if not line:
                await process._cancel_all()
                await runtime.shutdown()
                return 2
            if not await process.handle_line(line):
                return 0
    except (ProtocolError, OSError):
        await process._cancel_all()
        await runtime.shutdown()
        _stderr("protocol_failure")
        return 2


def _read_exact_private(path: Path, length: int) -> bytes:
    import os

    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        encoded = os.read(descriptor, length + 1)
    finally:
        os.close(descriptor)
    if len(encoded) != length:
        raise BridgeRuntimeError("authentication_failed")
    return encoded


def main() -> int:
    arguments = sys.argv[1:]
    if len(arguments) != 2 or arguments[0] not in {"--config", "--doctor-config"}:
        _stderr("startup_failed")
        return 2
    doctor_only = arguments[0] == "--doctor-config"
    config_path = Path(arguments[1])
    try:
        config = BridgeConfig.load(config_path)
        return asyncio.run(_run_stdio(config, doctor_only=doctor_only))
    except (ConfigError, OSError, RuntimeError):
        _stderr("startup_failed")
        return 2


def _stderr(code: str) -> None:
    try:
        sys.stderr.write(f"savana-openclaw-bridge: {code}\n")
        sys.stderr.flush()
    except OSError:
        pass
