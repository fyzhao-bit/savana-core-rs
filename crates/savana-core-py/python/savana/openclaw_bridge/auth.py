"""Out-of-band WebAuthn broker for the private Savana bridge."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
import stat
import struct
import threading
from typing import Any

AUTH_PROTOCOL_VERSION = 1
MAX_AUTH_FRAME_BYTES = 1024 * 1024
MAX_AUTH_FIELD_BYTES = 512 * 1024


class AuthBrokerError(Exception):
    """A redacted, fail-closed broker error."""


class WebAuthnBroker:
    """Synchronous SDK callback backed only by an inherited Unix socket."""

    def __init__(self, inherited_fd: int) -> None:
        if type(inherited_fd) is not int or inherited_fd < 3:
            raise AuthBrokerError("WebAuthn broker is unavailable")
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
        except (OSError, ValueError) as error:
            raise AuthBrokerError("WebAuthn broker is unavailable") from error
        self._channel = channel
        self._lock = threading.Lock()
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

    def close(self) -> None:
        with self._lock:
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

    def _roundtrip(self, encoded: bytes) -> dict[str, Any]:
        if not encoded or len(encoded) > MAX_AUTH_FRAME_BYTES:
            raise AuthBrokerError("authentication broker request is invalid")
        with self._lock:
            if self._closed:
                raise AuthBrokerError("authentication broker is unavailable")
            try:
                self._channel.sendall(struct.pack(">I", len(encoded)) + encoded)
                length = struct.unpack(">I", _read_exact(self._channel, 4))[0]
                if length == 0 or length > MAX_AUTH_FRAME_BYTES:
                    raise AuthBrokerError("authentication broker response is invalid")
                response = json.loads(
                    _read_exact(self._channel, length).decode("utf-8", errors="strict"),
                    object_pairs_hook=_unique_object,
                    parse_constant=_reject_constant,
                )
            except (
                OSError,
                UnicodeDecodeError,
                json.JSONDecodeError,
                struct.error,
            ) as error:
                raise AuthBrokerError("authentication broker is unavailable") from error
        if not isinstance(response, dict):
            raise AuthBrokerError("authentication broker response is invalid")
        return response


def _read_exact(channel: socket.socket, length: int) -> bytes:
    output = bytearray()
    while len(output) < length:
        chunk = channel.recv(length - len(output))
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
