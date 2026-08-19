import json
import os
from pathlib import Path

import pytest
from savana.openclaw_bridge.config import BridgeConfig, ConfigError
from savana.openclaw_bridge.protocol import (
    MAX_INBOUND_TEXT_BYTES,
    MAX_LINE_BYTES,
    MAX_RELEASED_TEXT_BYTES,
    PROTOCOL_VERSION,
    InboundDecoder,
    ProtocolError,
    encode_outbound,
)


def wire(kind, request_id, **payload):
    return (
        json.dumps(
            {
                "protocol_version": PROTOCOL_VERSION,
                "request_id": request_id,
                "type": kind,
                **payload,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def initialized_decoder():
    decoder = InboundDecoder()
    message = decoder.decode_line(
        wire(
            "initialize",
            1,
            openclaw_version="2026.7.1-2",
            plugin_version="0.1.0",
        )
    )
    assert message.type == "initialize"
    return decoder


def test_closed_inbound_union_and_monotonic_request_ids():
    decoder = initialized_decoder()
    messages = [
        decoder.decode_line(
            wire(
                "turn.start",
                2,
                agent_id="personal",
                session_id="session-1",
                turn_id="turn-1",
                text="帮我整理今天的安排",
            )
        ),
        decoder.decode_line(
            wire(
                "approval.answer",
                3,
                turn_request_id=2,
                approval_id="approval-1",
                approved=True,
            )
        ),
        decoder.decode_line(wire("turn.cancel", 4, turn_request_id=2)),
        decoder.decode_line(
            wire(
                "session.reset",
                5,
                agent_id="personal",
                session_id="session-1",
            )
        ),
        decoder.decode_line(wire("shutdown", 6)),
    ]
    assert [message.type for message in messages] == [
        "turn.start",
        "approval.answer",
        "turn.cancel",
        "session.reset",
        "shutdown",
    ]
    with pytest.raises(ProtocolError):
        decoder.decode_line(wire("shutdown", 7))


@pytest.mark.parametrize(
    "line",
    [
        b"not-json\n",
        b'{"protocol_version":1,"request_id":1,"type":"initialize","openclaw_version":"2026.7.1-2","plugin_version":NaN}\n',
        b'{"protocol_version":1,"protocol_version":1,"request_id":1,"type":"initialize","openclaw_version":"2026.7.1-2","plugin_version":"0.1.0"}\n',
        wire(
            "initialize",
            1,
            openclaw_version="2026.7.1-2",
            plugin_version="0.1.0",
            unknown=True,
        ),
        wire(
            "initialize",
            1,
            openclaw_version="next",
            plugin_version="0.1.0",
        ),
        wire("shutdown", 1),
    ],
)
def test_malformed_duplicate_unknown_version_or_wrong_order_fails_closed(line):
    with pytest.raises(ProtocolError):
        InboundDecoder().decode_line(line)


def test_request_ids_text_and_lines_are_bounded():
    decoder = initialized_decoder()
    with pytest.raises(ProtocolError):
        decoder.decode_line(
            wire(
                "turn.start",
                1,
                agent_id="personal",
                session_id="session-1",
                turn_id="turn-1",
                text="hello",
            )
        )
    with pytest.raises(ProtocolError):
        decoder.decode_line(
            wire(
                "turn.start",
                2,
                agent_id="personal",
                session_id="session-1",
                turn_id="turn-1",
                text="x" * (MAX_INBOUND_TEXT_BYTES + 1),
            )
        )
    with pytest.raises(ProtocolError):
        decoder.decode_line(b"{" + b" " * MAX_LINE_BYTES + b"\n")


def test_outbound_union_is_canonical_bounded_and_closed():
    encoded = encode_outbound(
        {
            "protocol_version": PROTOCOL_VERSION,
            "request_id": 9,
            "type": "turn.released",
            "text": "已完成",
        }
    )
    assert encoded.endswith(b"\n")
    assert len(encoded) <= MAX_LINE_BYTES
    assert json.loads(encoded) == {
        "protocol_version": PROTOCOL_VERSION,
        "request_id": 9,
        "type": "turn.released",
        "text": "已完成",
    }
    with pytest.raises(ProtocolError):
        encode_outbound(
            {
                "protocol_version": PROTOCOL_VERSION,
                "request_id": 9,
                "type": "turn.released",
                "text": "x" * (MAX_RELEASED_TEXT_BYTES + 1),
            }
        )
    with pytest.raises(ProtocolError):
        encode_outbound(
            {
                "protocol_version": PROTOCOL_VERSION,
                "request_id": 9,
                "type": "turn.failed",
                "code": "policy_refused",
                "detail": "private detail",
            }
        )


def write_private(path: Path, data: bytes = b"x"):
    path.write_bytes(data)
    os.chmod(path, 0o600)


def valid_config(tmp_path):
    paths = {}
    for name in (
        "identity",
        "client_root",
        "server_certificate",
        "server_private_key",
        "client_spki_pin",
    ):
        path = tmp_path / name
        write_private(path, b"a" * 32)
        paths[name] = str(path)
    return {
        "version": 1,
        "identity_path": paths["identity"],
        "webauthn_fd": 7,
        "release_journal_path": str(tmp_path / "release-journal.cbor"),
        "release_canonical_host": "provider.example",
        "client_root_certificate_path": paths["client_root"],
        "server_certificate_path": paths["server_certificate"],
        "server_private_key_path": paths["server_private_key"],
        "expected_client_spki_pin_path": paths["client_spki_pin"],
        "max_steps": 8,
        "max_replans": 2,
        "turn_timeout_seconds": 120.0,
    }


def test_config_is_closed_absolute_and_private(tmp_path):
    config_path = tmp_path / "bridge.json"
    payload = valid_config(tmp_path)
    write_private(config_path, json.dumps(payload).encode())
    config = BridgeConfig.load(config_path)
    assert config.version == 1
    assert config.webauthn_fd == 7
    assert config.max_steps == 8

    for mutation in (
        lambda value: value.update({"unknown": True}),
        lambda value: value.update({"identity_path": "relative"}),
        lambda value: value.update({"version": 2}),
        lambda value: value.update({"turn_timeout_seconds": 301}),
        lambda value: value.update({"bootstrap_token": "inline-secret"}),
    ):
        invalid = valid_config(tmp_path)
        mutation(invalid)
        write_private(config_path, json.dumps(invalid).encode())
        with pytest.raises(ConfigError):
            BridgeConfig.load(config_path)


def test_config_rejects_duplicate_keys_and_non_private_file(tmp_path):
    config_path = tmp_path / "bridge.json"
    write_private(config_path, b'{"version":1,"version":1}')
    with pytest.raises(ConfigError):
        BridgeConfig.load(config_path)

    payload = valid_config(tmp_path)
    write_private(config_path, json.dumps(payload).encode())
    os.chmod(config_path, 0o644)
    with pytest.raises(ConfigError):
        BridgeConfig.load(config_path)
