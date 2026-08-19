import asyncio
import base64
import hashlib
import json
import os
import socket
import ssl
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
import savana_core
from savana.openclaw_bridge.protocol import InboundDecoder
from savana.openclaw_bridge.runtime import BridgeProcess, BridgeRuntime


REPOSITORY = Path(__file__).resolve().parents[3]
TLS_FIXTURE = REPOSITORY / "crates/savana-execd/tests/fixtures/provider-tls-v2.hex"
ALPN = "savana-provider-v2"


def _fixture() -> dict[str, bytes]:
    return {
        name: bytes.fromhex(value)
        for name, value in (
            line.split("=", 1)
            for line in TLS_FIXTURE.read_text(encoding="ascii").splitlines()
        )
    }


def _der_element(encoded: bytes, offset: int, expected: int) -> tuple[int, int]:
    assert encoded[offset] == expected
    first = encoded[offset + 1]
    if first & 0x80 == 0:
        length, header = first, 2
    else:
        count = first & 0x7F
        assert 0 < count <= 4
        length = int.from_bytes(encoded[offset + 2 : offset + 2 + count], "big")
        header = 2 + count
    content = offset + header
    end = content + length
    assert end <= len(encoded)
    return content, end


def _der_any(encoded: bytes, offset: int) -> tuple[int, int]:
    return _der_element(encoded, offset, encoded[offset])


def _spki_pin(certificate: bytes) -> bytes:
    certificate_start, certificate_end = _der_element(certificate, 0, 0x30)
    assert certificate_end == len(certificate)
    tbs_start, tbs_end = _der_element(certificate, certificate_start, 0x30)
    tbs = certificate[tbs_start:tbs_end]
    offset = 0
    if tbs[offset] == 0xA0:
        _, offset = _der_element(tbs, offset, 0xA0)
    for _ in range(5):
        _, offset = _der_any(tbs, offset)
    _, spki_end = _der_element(tbs, offset, 0x30)
    return hashlib.sha256(tbs[offset:spki_end]).digest()


def _pem(label: str, encoded: bytes) -> bytes:
    body = base64.b64encode(encoded)
    lines = [body[index : index + 64] for index in range(0, len(body), 64)]
    return (
        f"-----BEGIN {label}-----\n".encode()
        + b"\n".join(lines)
        + f"\n-----END {label}-----\n".encode()
    )


def _private_file(path: Path, encoded: bytes) -> None:
    path.write_bytes(encoded)
    path.chmod(0o600)


def _cbor_head(major: int, length: int) -> bytes:
    if length < 24:
        return bytes([(major << 5) | length])
    if length <= 0xFF:
        return bytes([(major << 5) | 24, length])
    if length <= 0xFFFF:
        return bytes([(major << 5) | 25]) + length.to_bytes(2, "big")
    if length <= 0xFFFFFFFF:
        return bytes([(major << 5) | 26]) + length.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + length.to_bytes(8, "big")


def _cbor_integer(value: int) -> bytes:
    return _cbor_head(0, value)


def _cbor_bytes(value: bytes) -> bytes:
    return _cbor_head(2, len(value)) + value


def _cbor_text(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return _cbor_head(3, len(encoded)) + encoded


def _provider_request(canonical_url: str, server_pin: bytes, payload: bytes) -> bytes:
    prepared = hashlib.sha256(
        b"SAVANA_PREPARED_PROVIDER_REQUEST_V2\0" + payload
    ).digest()
    payload_digest = hashlib.sha256(
        b"SAVANA_PROVIDER_REQUEST_PAYLOAD_V2\0"
        + len(payload).to_bytes(8, "big")
        + payload
    ).digest()
    values = (
        _cbor_integer(2),
        _cbor_integer(1),
        _cbor_text(canonical_url),
        _cbor_bytes(server_pin),
        _cbor_bytes(bytes([0x51]) * 32),
        _cbor_bytes(bytes([0x52]) * 32),
        _cbor_bytes(bytes([0x53]) * 32),
        _cbor_integer(len(payload)),
        _cbor_bytes(prepared),
        _cbor_bytes(payload_digest),
        _cbor_bytes(payload),
    )
    return _cbor_head(4, len(values)) + b"".join(values)


def _send_release(
    canonical_url: str,
    payload: bytes,
    ca_path: Path,
    client_certificate_path: Path,
    client_key_path: Path,
    server_pin: bytes,
) -> None:
    target = urlsplit(canonical_url)
    assert target.hostname == "provider.example"
    assert target.port is not None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=str(ca_path))
    context.load_cert_chain(str(client_certificate_path), str(client_key_path))
    context.set_alpn_protocols([ALPN])
    with socket.create_connection(("127.0.0.1", target.port), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname=target.hostname) as tls:
            assert tls.selected_alpn_protocol() == ALPN
            tls.sendall(_provider_request(canonical_url, server_pin, payload))
            acknowledgement = tls.recv(128)
            assert acknowledgement and acknowledgement[0] == 0x83


def _decode_item(encoded: bytes, offset: int = 0):
    initial = encoded[offset]
    major, additional = initial >> 5, initial & 0x1F
    offset += 1
    if additional < 24:
        length = additional
    else:
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        width = widths[additional]
        length = int.from_bytes(encoded[offset : offset + width], "big")
        offset += width
    if major == 0:
        return length, offset
    if major in (2, 3):
        end = offset + length
        value = encoded[offset:end]
        return (value.decode() if major == 3 else value), end
    if major == 4:
        values = []
        for _ in range(length):
            value, offset = _decode_item(encoded, offset)
            values.append(value)
        return values, offset
    raise AssertionError("unsupported fixture CBOR")


class _Choice:
    def __init__(self, value: str) -> None:
        self.value = value


class _Limits:
    def __init__(self, max_steps: int, max_replans: int, timeout: float) -> None:
        self.values = (max_steps, max_replans, timeout)
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True


class _Sdk:
    ContentKind = SimpleNamespace(CHAT_TEXT=_Choice("chat_text"))
    IntentPrivacy = SimpleNamespace(PRIVATE=_Choice("private"))
    RunLimits = _Limits


class _Session:
    def __init__(self, deliver, *, connector_effect: bool) -> None:
        self._deliver = deliver
        self._connector_effect = connector_effect

    async def ingest_text(self, text, content_kind) -> None:
        assert text == "current inbound text"
        assert content_kind.value == "chat_text"

    async def run_agent(self, privacy, limits, approval, events):
        assert privacy.value == "private"
        await asyncio.to_thread(events, SimpleNamespace(kind="planning"))
        if self._connector_effect:
            approved = await asyncio.to_thread(
                approval,
                SimpleNamespace(
                    display="Approve exact connector effect",
                    purpose="tool_execution",
                ),
            )
            assert approved is True
        return SimpleNamespace(
            status="succeeded",
            outputs=[SimpleNamespace(kind="document")],
        )

    async def release(self, document, approval):
        assert document.kind == "document"
        approved = await asyncio.to_thread(
            approval,
            SimpleNamespace(
                display="Approve exact final release",
                purpose="final_release",
            ),
        )
        assert approved is True
        await asyncio.to_thread(self._deliver)
        return SimpleNamespace(status="succeeded")

    async def close(self) -> None:
        return None


class _Client:
    def __init__(self, session) -> None:
        self._session = session

    async def session(self, identity, bootstrap, webauthn, approval):
        assert bootstrap == "fresh-bootstrap"
        return self._session


class _Bootstrap:
    async def next(self) -> str:
        return "fresh-bootstrap"


@pytest.mark.asyncio
@pytest.mark.parametrize("connector_effect", [False, True])
async def test_only_durably_claimed_mtls_payload_becomes_assistant_text(
    tmp_path: Path, connector_effect: bool
) -> None:
    fixture = _fixture()
    ca_path = tmp_path / "ca.pem"
    server_certificate_path = tmp_path / "server.der"
    server_key_path = tmp_path / "server.key"
    client_certificate_path = tmp_path / "client.pem"
    client_key_path = tmp_path / "client.key"
    receiver_ca_path = tmp_path / "ca.der"
    journal_path = tmp_path / "release.cbor"
    _private_file(ca_path, _pem("CERTIFICATE", fixture["ca_cert"]))
    _private_file(receiver_ca_path, fixture["ca_cert"])
    _private_file(server_certificate_path, fixture["server_cert"])
    _private_file(server_key_path, fixture["server_key"])
    _private_file(
        client_certificate_path, _pem("CERTIFICATE", fixture["client_cert"])
    )
    _private_file(client_key_path, _pem("PRIVATE KEY", fixture["client_key"]))

    receiver = savana_core._ReleaseReceiver(
        str(journal_path),
        "provider.example",
        str(receiver_ca_path),
        str(server_certificate_path),
        str(server_key_path),
        _spki_pin(fixture["client_cert"]),
    )
    payload = (
        b"released connector result" if connector_effect else b"released private answer"
    )
    deliver = lambda: _send_release(
        receiver.canonical_url,
        payload,
        ca_path,
        client_certificate_path,
        client_key_path,
        _spki_pin(fixture["server_cert"]),
    )
    emitted: list[dict] = []
    journal_at_release: bytes | None = None
    approval_request_id = 90
    process: BridgeProcess
    decoder = InboundDecoder()

    async def writer(message: dict) -> None:
        nonlocal approval_request_id, journal_at_release
        emitted.append(message)
        if message["type"] == "approval.request":
            request_id = approval_request_id
            approval_request_id += 1
            await process.handle(
                decoder.decode_line(
                    json.dumps(
                        {
                            "protocol_version": 1,
                            "request_id": request_id,
                            "type": "approval.answer",
                            "turn_request_id": message["request_id"],
                            "approval_id": message["approval_id"],
                            "approved": True,
                        },
                        separators=(",", ":"),
                    ).encode()
                    + b"\n"
                )
            )
        if message["type"] == "turn.released":
            journal_at_release = journal_path.read_bytes()

    runtime = BridgeRuntime(
        client=_Client(_Session(deliver, connector_effect=connector_effect)),
        identity="identity",
        bootstrap_source=_Bootstrap(),
        webauthn=SimpleNamespace(close=lambda: None),
        receiver=receiver,
        sdk=_Sdk,
        max_steps=8,
        max_replans=2,
        turn_timeout_seconds=3.0,
        emit=writer,
    )
    process = BridgeProcess(runtime, writer)
    assert await process.handle(
        decoder.decode_line(
            b'{"protocol_version":1,"request_id":1,"type":"initialize","openclaw_version":"2026.7.1-2","plugin_version":"0.1.0"}\n'
        )
    )
    assert await process.handle(
        decoder.decode_line(
            b'{"protocol_version":1,"request_id":2,"type":"turn.start","agent_id":"personal","session_id":"opaque-session","turn_id":"run-1","text":"current inbound text"}\n'
        )
    )
    await process.wait_idle()

    terminals = [
        message
        for message in emitted
        if message["type"] in {"turn.released", "turn.failed"}
    ]
    assert terminals == [
        {
            "protocol_version": 1,
            "request_id": 2,
            "type": "turn.released",
            "text": payload.decode(),
        }
    ]
    assert journal_at_release is not None
    journal, end = _decode_item(journal_at_release)
    assert end == len(journal_at_release)
    assert journal[2][0] == 2  # claimed
    assert journal[2][-1] == payload
    assert terminals[0]["text"].encode() == journal[2][-1]
    await runtime.shutdown()


def test_real_receiver_rejects_cross_session_reservation(tmp_path: Path) -> None:
    fixture = _fixture()
    ca = tmp_path / "ca.der"
    server = tmp_path / "server.der"
    key = tmp_path / "server.key"
    for path, encoded in (
        (ca, fixture["ca_cert"]),
        (server, fixture["server_cert"]),
        (key, fixture["server_key"]),
    ):
        _private_file(path, encoded)
    receiver = savana_core._ReleaseReceiver(
        str(tmp_path / "release.cbor"),
        "provider.example",
        str(ca),
        str(server),
        str(key),
        _spki_pin(fixture["client_cert"]),
    )
    receiver.reserve(os.urandom(32), 2.0)
    with pytest.raises(RuntimeError) as failure:
        receiver.reserve(os.urandom(32), 2.0)
    assert failure.value.code == "release_busy"
    receiver.close()
