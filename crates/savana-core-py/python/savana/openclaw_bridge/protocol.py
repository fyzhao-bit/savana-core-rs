"""Strict, bounded NDJSON protocol between OpenClaw and the Savana bridge."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

PROTOCOL_VERSION = 1
OPENCLAW_VERSION = "2026.7.1-2"
BRIDGE_VERSION = "0.1.0"
MAX_LINE_BYTES = 1024 * 1024
MAX_INBOUND_TEXT_BYTES = 256 * 1024
MAX_RELEASED_TEXT_BYTES = 1024 * 1024
MAX_ID_BYTES = 256
MAX_REQUEST_ID = (1 << 53) - 1


class ProtocolError(Exception):
    """A redacted, terminal bridge protocol violation."""


@dataclass(frozen=True, slots=True)
class InboundMessage:
    protocol_version: int
    request_id: int
    type: str
    payload: Mapping[str, Any]


_INBOUND_KEYS = {
    "initialize": frozenset(
        {
            "protocol_version",
            "request_id",
            "type",
            "openclaw_version",
            "plugin_version",
        }
    ),
    "turn.start": frozenset(
        {
            "protocol_version",
            "request_id",
            "type",
            "agent_id",
            "session_id",
            "turn_id",
            "text",
        }
    ),
    "turn.cancel": frozenset(
        {"protocol_version", "request_id", "type", "turn_request_id"}
    ),
    "session.reset": frozenset(
        {"protocol_version", "request_id", "type", "agent_id", "session_id"}
    ),
    "doctor.request": frozenset({"protocol_version", "request_id", "type"}),
    "shutdown": frozenset({"protocol_version", "request_id", "type"}),
}

_OUTBOUND_KEYS = {
    "initialized": frozenset(
        {
            "protocol_version",
            "request_id",
            "type",
            "bridge_version",
        }
    ),
    "turn.event": None,
    "turn.released": frozenset({"protocol_version", "request_id", "type", "text"}),
    "turn.failed": frozenset({"protocol_version", "request_id", "type", "code"}),
    "session.closed": frozenset({"protocol_version", "request_id", "type"}),
    "doctor.result": frozenset(
        {
            "protocol_version",
            "request_id",
            "type",
            "active_connector_count",
            "release_target_url",
            "service_origins",
        }
    ),
    "doctor.failed": frozenset(
        {"protocol_version", "request_id", "type", "code"}
    ),
}

_EVENT_KEYS = {
    "planning": frozenset({"protocol_version", "request_id", "type", "event"}),
    "step_started": frozenset(
        {"protocol_version", "request_id", "type", "event", "index"}
    ),
    "step_completed": frozenset(
        {
            "protocol_version",
            "request_id",
            "type",
            "event",
            "index",
            "status",
        }
    ),
    "approval_required": frozenset(
        {"protocol_version", "request_id", "type", "event", "purpose"}
    ),
    "replanning": frozenset(
        {"protocol_version", "request_id", "type", "event", "count"}
    ),
    "refused": frozenset({"protocol_version", "request_id", "type", "event"}),
    "completed": frozenset({"protocol_version", "request_id", "type", "event"}),
}

_PURPOSES = {
    "ingress",
    "tool_execution",
    "final_release",
    "connector_registration",
    "task_authorization",
}
_STATUSES = {
    "succeeded",
    "effect_succeeded_output_quarantined",
    "failed_no_effect",
}
_FAILURE_CODES = {
    "authentication_failed",
    "approval_denied",
    "policy_refused",
    "cancelled",
    "deadline_exceeded",
    "runtime_incompatible",
    "protocol_failure",
    "delivery_timeout",
    "indeterminate",
    "no_output",
    "internal_failure",
}


class InboundDecoder:
    def __init__(self) -> None:
        self._last_request_id = 0
        self._initialized = False
        self._closed = False

    def decode_line(self, line: bytes) -> InboundMessage:
        if self._closed:
            raise ProtocolError("bridge protocol is closed")
        value = _decode_json_line(line)
        kind = value.get("type")
        if not isinstance(kind, str) or kind not in _INBOUND_KEYS:
            raise ProtocolError("unsupported bridge message")
        _require_exact_keys(value, _INBOUND_KEYS[kind])
        _require_protocol_version(value.get("protocol_version"))
        request_id = _require_request_id(value.get("request_id"))
        if request_id <= self._last_request_id:
            raise ProtocolError("bridge request ids are not monotonic")
        if not self._initialized and kind != "initialize":
            raise ProtocolError("bridge is not initialized")
        if self._initialized and kind == "initialize":
            raise ProtocolError("bridge is already initialized")
        _validate_inbound_payload(kind, value)

        self._last_request_id = request_id
        if kind == "initialize":
            self._initialized = True
        elif kind == "shutdown":
            self._closed = True
        payload = {
            key: item
            for key, item in value.items()
            if key not in {"protocol_version", "request_id", "type"}
        }
        return InboundMessage(
            protocol_version=PROTOCOL_VERSION,
            request_id=request_id,
            type=kind,
            payload=MappingProxyType(payload),
        )


def encode_outbound(message: Mapping[str, Any]) -> bytes:
    if not isinstance(message, Mapping):
        raise ProtocolError("invalid outbound bridge message")
    value = dict(message)
    kind = value.get("type")
    if not isinstance(kind, str) or kind not in _OUTBOUND_KEYS:
        raise ProtocolError("unsupported outbound bridge message")
    keys = _OUTBOUND_KEYS[kind]
    if kind == "turn.event":
        event = value.get("event")
        if not isinstance(event, str) or event not in _EVENT_KEYS:
            raise ProtocolError("unsupported bridge event")
        keys = _EVENT_KEYS[event]
    _require_exact_keys(value, keys)
    _require_protocol_version(value.get("protocol_version"))
    _require_request_id(value.get("request_id"))
    _validate_outbound_payload(kind, value)
    try:
        encoded = (
            json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ProtocolError("invalid outbound bridge message") from error
    if len(encoded) > MAX_LINE_BYTES:
        raise ProtocolError("outbound bridge line is oversized")
    return encoded


def _decode_json_line(line: bytes) -> dict[str, Any]:
    if (
        not isinstance(line, bytes)
        or not line.endswith(b"\n")
        or line.endswith(b"\r\n")
        or b"\n" in line[:-1]
        or len(line) > MAX_LINE_BYTES
    ):
        raise ProtocolError("invalid bridge line")
    try:
        text = line[:-1].decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_closed_object,
            parse_constant=_reject_constant,
        )
    except (
        UnicodeDecodeError,
        UnicodeEncodeError,
        json.JSONDecodeError,
        ProtocolError,
    ) as error:
        raise ProtocolError("invalid bridge JSON") from error
    if not isinstance(value, dict):
        raise ProtocolError("bridge message must be an object")
    return value


def _closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate bridge key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ProtocolError("non-finite bridge number")


def _require_exact_keys(value: Mapping[str, Any], expected: frozenset[str]) -> None:
    if frozenset(value) != expected:
        raise ProtocolError("bridge object shape is invalid")


def _require_protocol_version(value: Any) -> None:
    if type(value) is not int or value != PROTOCOL_VERSION:
        raise ProtocolError("bridge protocol version mismatch")


def _require_request_id(value: Any) -> int:
    if type(value) is not int or value <= 0 or value > MAX_REQUEST_ID:
        raise ProtocolError("invalid bridge request id")
    return value


def _bounded_string(value: Any, maximum: int, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ProtocolError("invalid bounded bridge string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ProtocolError("invalid bounded bridge string") from error
    if len(encoded) > maximum or "\x00" in value:
        raise ProtocolError("invalid bounded bridge string")
    return value


def _bounded_id(value: Any) -> str:
    value = _bounded_string(value, MAX_ID_BYTES)
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ProtocolError("invalid bridge identifier")
    return value


def _bounded_u32(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ProtocolError("invalid bridge integer")
    return value


def _validate_inbound_payload(kind: str, value: Mapping[str, Any]) -> None:
    if kind == "initialize":
        if value["openclaw_version"] != OPENCLAW_VERSION:
            raise ProtocolError("OpenClaw compatibility version mismatch")
        if value["plugin_version"] != BRIDGE_VERSION:
            raise ProtocolError("bridge plugin version mismatch")
    elif kind == "turn.start":
        _bounded_id(value["agent_id"])
        _bounded_id(value["session_id"])
        _bounded_id(value["turn_id"])
        _bounded_string(value["text"], MAX_INBOUND_TEXT_BYTES)
    elif kind == "turn.cancel":
        _require_request_id(value["turn_request_id"])
    elif kind == "session.reset":
        _bounded_id(value["agent_id"])
        _bounded_id(value["session_id"])


def _validate_outbound_payload(kind: str, value: Mapping[str, Any]) -> None:
    if kind == "initialized":
        if value["bridge_version"] != BRIDGE_VERSION:
            raise ProtocolError("bridge version mismatch")
    elif kind == "turn.event":
        event = value["event"]
        if "index" in value:
            _bounded_u32(value["index"])
        if "count" in value:
            _bounded_u32(value["count"])
        if "status" in value and (
            not isinstance(value["status"], str) or value["status"] not in _STATUSES
        ):
            raise ProtocolError("invalid bridge execution status")
        if "purpose" in value and (
            not isinstance(value["purpose"], str) or value["purpose"] not in _PURPOSES
        ):
            raise ProtocolError("invalid bridge approval purpose")
        if event not in _EVENT_KEYS:
            raise ProtocolError("invalid bridge event")
    elif kind == "turn.released":
        _bounded_string(value["text"], MAX_RELEASED_TEXT_BYTES)
    elif kind == "doctor.result":
        _bounded_u32(value["active_connector_count"])
        _bounded_string(value["release_target_url"], 4096)
        origins = value["service_origins"]
        if (
            not isinstance(origins, list)
            or len(origins) != 3
            or any(not isinstance(origin, str) for origin in origins)
        ):
            raise ProtocolError("invalid service origins")
        for origin in origins:
            _bounded_string(origin, 256)
    elif kind in {"turn.failed", "doctor.failed"} and (
        not isinstance(value["code"], str) or value["code"] not in _FAILURE_CODES
    ):
        raise ProtocolError("invalid bridge failure code")


def main() -> int:
    from .runtime import main as runtime_main

    return runtime_main()
