"""Out-of-band WebAuthn broker for the private Savana bridge."""

from __future__ import annotations

import asyncio
import base64
import json
import math
import os
import re
import secrets
import socket
import stat
import struct
import threading
import time
import unicodedata
from typing import Any

AUTH_PROTOCOL_VERSION = 1
MAX_AUTH_FRAME_BYTES = 1024 * 1024
MAX_AUTH_FIELD_BYTES = 512 * 1024
MAX_APPROVAL_DISPLAY_BYTES = 16 * 1024
MAX_APPROVAL_IDS = 65_536
APPROVAL_PURPOSES = frozenset(
    {"ingress", "tool_execution", "final_release", "connector_registration", "task_authorization"}
)
_APPROVAL_ID = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class AuthBrokerError(Exception):
    """A redacted, fail-closed broker error."""


class WebAuthnBroker:
    """Synchronous SDK callback backed only by an inherited Unix socket."""

    def __init__(self, inherited_fd: int, *, timeout_seconds: float = 30.0) -> None:
        if (
            type(inherited_fd) is not int
            or inherited_fd < 3
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 300
        ):
            raise AuthBrokerError("WebAuthn broker is unavailable")
        channel: socket.socket | None = None
        try:
            metadata = os.fstat(inherited_fd)
            if not stat.S_ISSOCK(metadata.st_mode):
                raise AuthBrokerError("WebAuthn broker is unavailable")
            duplicated = os.dup(inherited_fd)
            channel = socket.socket(fileno=duplicated)
            if (
                channel.family != socket.AF_UNIX
                or channel.type & socket.SOCK_STREAM == 0
            ):
                channel.close()
                raise AuthBrokerError("WebAuthn broker is unavailable")
            channel.settimeout(float(timeout_seconds))
        except (OSError, ValueError) as error:
            if channel is not None:
                channel.close()
            raise AuthBrokerError("WebAuthn broker is unavailable") from error
        self._channel = channel
        self._lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._approval_id_lock = threading.Lock()
        self._issued_approval_ids: set[str] = set()
        self._timeout_seconds = float(timeout_seconds)
        self._closed = False

    def assert_credential(self, options_json: bytes) -> dict[str, bytes]:
        return self._exchange(
            "webauthn.assert",
            "webauthn.assertion",
            options_json,
            (
                "credential_id",
                "authenticator_data",
                "client_data_json",
                "signature",
                "user_handle",
            ),
        )

    def create_credential(self, options_json: bytes) -> dict[str, bytes]:
        return self._exchange(
            "webauthn.create",
            "webauthn.attestation",
            options_json,
            ("credential_id", "client_data_json", "attestation_object"),
        )

    async def next(self) -> str:
        """Obtain a fresh one-use session bootstrap on the same private channel."""
        return await asyncio.to_thread(self._next_bootstrap)

    def request_task_draft(
        self,
        context: Any,
        turn_binding: bytes,
        deadline_unix_ms: int,
        cancel_event: threading.Event | None = None,
    ) -> bytes | None:
        """Return bounded unsigned clause JSON from the out-of-band scope editor.

        No raw input or credentials are sent. The response cannot select source,
        principal, task, profile or revision; Rust fills those from the context.
        This is deliberately separate from approval.decide and WebAuthn.
        """
        source = context.source_input_digest
        tools = context.tools_json()
        identity = context.authorization_identity
        if (
            not isinstance(turn_binding, bytes) or len(turn_binding) != 32 or not any(turn_binding)
            or not isinstance(source, bytes) or len(source) != 32 or not any(source)
            or not isinstance(tools, str)
            or type(deadline_unix_ms) is not int
            or not int(time.time() * 1000) < deadline_unix_ms <= (1 << 63) - 1
        ):
            raise AuthBrokerError("task draft request is invalid")
        tools_bytes = tools.encode("utf-8", errors="strict")
        if len(tools_bytes) > MAX_AUTH_FIELD_BYTES:
            raise AuthBrokerError("task draft request is oversized")
        request_id = self._fresh_approval_id()
        request = {
            "protocol_version": AUTH_PROTOCOL_VERSION,
            "type": "task.draft",
            "draft_id": request_id,
            "source_input_digest": source.hex(),
            "release_destination": "application-turn:" + turn_binding.hex(),
            "tools_json": _encode_binary(tools_bytes),
            "next_revision": 1 if identity is None else identity[1],
            "deadline_unix_ms": deadline_unix_ms,
        }
        encoded = json.dumps(request, separators=(",", ":"), sort_keys=True).encode("ascii")
        remaining = (deadline_unix_ms - int(time.time() * 1000)) / 1000.0
        response = self._roundtrip(
            encoded,
            monotonic_deadline=time.monotonic() + min(self._timeout_seconds, remaining),
            cancel_event=cancel_event,
        )
        if (
            frozenset(response) != {"protocol_version", "type", "draft_id", "clauses_json"}
            or type(response.get("protocol_version")) is not int
            or response["protocol_version"] != AUTH_PROTOCOL_VERSION
            or response.get("type") != "task.draft_result"
            or not isinstance(response.get("draft_id"), str)
            or not secrets.compare_digest(response["draft_id"], request_id)
        ):
            raise AuthBrokerError("task draft response is invalid")
        if response["clauses_json"] is None:
            return None
        return _decode_binary(response["clauses_json"])

    def decide_approval(
        self,
        display: str,
        purpose: str,
        deadline_unix_ms: int,
        cancel_event: threading.Event | None = None,
    ) -> bool:
        if not isinstance(display, str) or not display:
            raise AuthBrokerError("approval broker request is invalid")
        try:
            display_bytes = display.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise AuthBrokerError("approval broker request is invalid") from error
        if (
            unicodedata.normalize("NFC", display) != display
            or any(unicodedata.category(character) == "Cc" for character in display)
            or len(display_bytes) > MAX_APPROVAL_DISPLAY_BYTES
            or not isinstance(purpose, str)
            or purpose not in APPROVAL_PURPOSES
            or type(deadline_unix_ms) is not int
            or deadline_unix_ms <= int(time.time() * 1000)
            or deadline_unix_ms > (1 << 63) - 1
        ):
            raise AuthBrokerError("approval broker request is invalid")
        approval_id = self._fresh_approval_id()
        request = {
            "protocol_version": AUTH_PROTOCOL_VERSION,
            "type": "approval.decide",
            "approval_id": approval_id,
            "display": display,
            "purpose": purpose,
            "deadline_unix_ms": deadline_unix_ms,
        }
        encoded = json.dumps(
            request,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(encoded) > MAX_AUTH_FRAME_BYTES:
            raise AuthBrokerError("approval broker request is oversized")
        remaining = (deadline_unix_ms - int(time.time() * 1000)) / 1000.0
        if remaining <= 0:
            raise AuthBrokerError("approval broker request is expired")
        monotonic_deadline = time.monotonic() + min(
            self._timeout_seconds, remaining
        )
        response = self._roundtrip(
            encoded,
            monotonic_deadline=monotonic_deadline,
            cancel_event=cancel_event,
        )
        if (
            frozenset(response)
            != {"protocol_version", "type", "approval_id", "approved"}
            or response.get("protocol_version") != AUTH_PROTOCOL_VERSION
            or response.get("type") != "approval.decision"
            or not isinstance(response.get("approval_id"), str)
            or not secrets.compare_digest(response["approval_id"], approval_id)
            or type(response.get("approved")) is not bool
        ):
            raise AuthBrokerError("approval broker response is invalid")
        return response["approved"]

    def _fresh_approval_id(self) -> str:
        with self._approval_id_lock:
            if len(self._issued_approval_ids) >= MAX_APPROVAL_IDS:
                raise AuthBrokerError("approval broker is unavailable")
            for _ in range(4):
                approval_id = secrets.token_urlsafe(32)
                if (
                    _APPROVAL_ID.fullmatch(approval_id)
                    and approval_id not in self._issued_approval_ids
                ):
                    self._issued_approval_ids.add(approval_id)
                    return approval_id
        raise AuthBrokerError("approval broker is unavailable")

    def close(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._channel.close()

    def _exchange(
        self,
        request_type: str,
        response_type: str,
        options_json: bytes,
        response_fields: tuple[str, ...],
    ) -> dict[str, bytes]:
        if not isinstance(options_json, bytes) or not options_json:
            raise AuthBrokerError("WebAuthn broker request is invalid")
        if len(options_json) > MAX_AUTH_FIELD_BYTES:
            raise AuthBrokerError("WebAuthn broker request is oversized")
        request = {
            "protocol_version": AUTH_PROTOCOL_VERSION,
            "type": request_type,
            "options_json": _encode_binary(options_json),
        }
        encoded = json.dumps(
            request,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        if len(encoded) > MAX_AUTH_FRAME_BYTES:
            raise AuthBrokerError("WebAuthn broker request is oversized")
        response = self._roundtrip(encoded)
        expected = frozenset({"protocol_version", "type", *response_fields})
        if (
            not isinstance(response, dict)
            or frozenset(response) != expected
            or response.get("protocol_version") != AUTH_PROTOCOL_VERSION
            or response.get("type") != response_type
        ):
            raise AuthBrokerError("WebAuthn broker response is invalid")
        return {field: _decode_binary(response[field]) for field in response_fields}

    def _next_bootstrap(self) -> str:
        encoded = json.dumps(
            {
                "protocol_version": AUTH_PROTOCOL_VERSION,
                "type": "session.bootstrap",
            },
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        response = self._roundtrip(encoded)
        if (
            not isinstance(response, dict)
            or frozenset(response)
            != {"protocol_version", "type", "control_plane_token"}
            or response.get("protocol_version") != AUTH_PROTOCOL_VERSION
            or response.get("type") != "session.bootstrap_token"
        ):
            raise AuthBrokerError("session bootstrap broker response is invalid")
        token = response["control_plane_token"]
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 128
            or not token.isascii()
            or any(character.isspace() for character in token)
        ):
            raise AuthBrokerError("session bootstrap broker response is invalid")
        return token

    def _roundtrip(
        self,
        encoded: bytes,
        *,
        monotonic_deadline: float | None = None,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        if not encoded or len(encoded) > MAX_AUTH_FRAME_BYTES:
            raise AuthBrokerError("authentication broker request is invalid")
        deadline = (
            time.monotonic() + self._timeout_seconds
            if monotonic_deadline is None
            else monotonic_deadline
        )
        acquired = False
        previous_timeout: float | None = None
        try:
            while not acquired:
                remaining = _remaining_seconds(deadline, cancel_event)
                acquired = self._lock.acquire(
                    timeout=min(remaining, 0.1 if cancel_event is not None else remaining)
                )
            with self._state_lock:
                if self._closed:
                    raise AuthBrokerError("authentication broker is unavailable")
            previous_timeout = self._channel.gettimeout()
            _write_all(
                self._channel,
                struct.pack(">I", len(encoded)) + encoded,
                deadline,
                cancel_event,
            )
            length = struct.unpack(
                ">I", _read_exact(self._channel, 4, deadline, cancel_event)
            )[0]
            if length == 0 or length > MAX_AUTH_FRAME_BYTES:
                raise AuthBrokerError("authentication broker response is invalid")
            response = json.loads(
                _read_exact(self._channel, length, deadline, cancel_event).decode(
                    "utf-8", errors="strict"
                ),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
            _remaining_seconds(deadline, cancel_event)
        except AuthBrokerError:
            if acquired:
                self.close()
            raise
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            struct.error,
        ) as error:
            if acquired:
                self.close()
            raise AuthBrokerError("authentication broker is unavailable") from error
        finally:
            if acquired:
                if previous_timeout is not None:
                    try:
                        self._channel.settimeout(previous_timeout)
                    except OSError:
                        pass
                self._lock.release()
        if not isinstance(response, dict):
            raise AuthBrokerError("authentication broker response is invalid")
        return response


def _remaining_seconds(
    monotonic_deadline: float,
    cancel_event: threading.Event | None,
) -> float:
    if cancel_event is not None and cancel_event.is_set():
        raise AuthBrokerError("authentication broker request was cancelled")
    remaining = monotonic_deadline - time.monotonic()
    if remaining <= 0:
        raise AuthBrokerError("authentication broker request expired")
    return remaining


def _io_timeout(remaining: float, cancel_event: threading.Event | None) -> float:
    return min(remaining, 0.1 if cancel_event is not None else remaining)


def _write_all(
    channel: socket.socket,
    encoded: bytes,
    monotonic_deadline: float,
    cancel_event: threading.Event | None,
) -> None:
    view = memoryview(encoded)
    while view:
        remaining = _remaining_seconds(monotonic_deadline, cancel_event)
        channel.settimeout(_io_timeout(remaining, cancel_event))
        try:
            written = channel.send(view)
        except socket.timeout:
            continue
        if written <= 0:
            raise AuthBrokerError("authentication broker closed")
        view = view[written:]


def _read_exact(
    channel: socket.socket,
    length: int,
    monotonic_deadline: float,
    cancel_event: threading.Event | None,
) -> bytes:
    output = bytearray()
    while len(output) < length:
        remaining = _remaining_seconds(monotonic_deadline, cancel_event)
        channel.settimeout(_io_timeout(remaining, cancel_event))
        try:
            chunk = channel.recv(length - len(output))
        except socket.timeout:
            continue
        if not chunk:
            raise AuthBrokerError("WebAuthn broker closed")
        output.extend(chunk)
    return bytes(output)


def _encode_binary(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_binary(value: Any) -> bytes:
    if not isinstance(value, str) or not value or len(value) > MAX_AUTH_FIELD_BYTES * 2:
        raise AuthBrokerError("WebAuthn broker response is invalid")
    try:
        padding = "=" * ((4 - len(value) % 4) % 4)
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, UnicodeEncodeError) as error:
        raise AuthBrokerError("WebAuthn broker response is invalid") from error
    if (
        not decoded
        or len(decoded) > MAX_AUTH_FIELD_BYTES
        or _encode_binary(decoded) != value
    ):
        raise AuthBrokerError("WebAuthn broker response is invalid")
    return decoded


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthBrokerError("WebAuthn broker response is invalid")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise AuthBrokerError("WebAuthn broker response is invalid")
