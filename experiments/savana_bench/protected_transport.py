"""Authenticated *business provider* endpoint, not a kernel IPC client.

Implements execd's existing TLS 1.3 / canonical 11-field provider frame. Only
the pinned deployment client may reach the benchmark tools. No HTTP, arbitrary
tool routing, policy approval, signing key or SDK capability is accepted here.
"""
from dataclasses import dataclass, field
import hashlib
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

MAX_FRAME = 65536
MAX_PAYLOAD = 49152  # 32 KiB final output plus base64 and business envelope


def _head(major, size):
    if size < 24:
        return bytes([(major << 5) | size])
    for width, marker in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if size < 1 << (8 * width):
            return bytes([(major << 5) | marker]) + size.to_bytes(width, "big")
    raise ValueError("frame_integer_bound")


def _blob(major, value):
    return _head(major, len(value)) + value


def _hash(domain, value, *, length=False):
    return hashlib.sha256(domain + (len(value).to_bytes(8, "big") if length else b"") + value).digest()


@dataclass(frozen=True, repr=False)
class ProviderFrame:
    url: str
    pin: bytes
    nonce: bytes
    core: bytes
    subject: bytes
    payload: bytes = field(repr=False)
    wire_digest: bytes


def read_frame(read):
    """Closed canonical decoder; read(n) must return exactly n bytes."""
    wire = bytearray()

    def take(n):
        if n < 0 or len(wire) + n > MAX_FRAME:
            raise ValueError("frame_size")
        value = read(n)
        if len(value) != n:
            raise EOFError("truncated_frame")
        wire.extend(value)
        return value

    def head(major):
        first = take(1)[0]
        if first >> 5 != major:
            raise ValueError("frame_type")
        additional = first & 31
        if additional < 24:
            return additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        if additional not in widths:
            raise ValueError("indefinite_frame")
        raw = bytes([first]) + take(widths[additional])
        size = int.from_bytes(raw[1:], "big")
        if _head(major, size) != raw:
            raise ValueError("noncanonical_frame")
        return size

    def blob(major, maximum, exact=None):
        size = head(major)
        if not 0 < size <= maximum or (exact is not None and size != exact):
            raise ValueError("field_size")
        return take(size)

    if head(4) != 11 or head(0) != 2 or head(0) != 1:
        raise ValueError("provider_frame_version")
    url = blob(3, 4096).decode("utf-8", errors="strict")
    pin, nonce, core, subject = (blob(2, 32, 32) for _ in range(4))
    size = head(0)
    prepared, payload_digest = (blob(2, 32, 32) for _ in range(2))
    payload = blob(2, MAX_PAYLOAD)
    if (size != len(payload) or any(v == bytes(32) for v in (pin, nonce, core, subject))
        or prepared != _hash(b"SAVANA_PREPARED_PROVIDER_REQUEST_V2\0", payload)
        or payload_digest != _hash(b"SAVANA_PROVIDER_REQUEST_PAYLOAD_V2\0", payload, length=True)):
        raise ValueError("provider_frame_binding")
    return ProviderFrame(url, pin, nonce, core, subject, payload,
        _hash(b"SAVANA_BOUND_PROVIDER_REQUEST_WIRE_V2\0", bytes(wire), length=True))


def server_context(*, certificate, private_key, client_ca, alpn):
    if type(alpn) is not str or not 0 < len(alpn.encode("ascii")) <= 255:
        raise ValueError("alpn_required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certificate, private_key)
    context.load_verify_locations(cafile=client_ca)
    context.set_alpn_protocols([alpn])
    context.num_tickets = 0
    return context


def certificate_spki_pin(certificate):
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from pathlib import Path
    cert = x509.load_pem_x509_certificate(Path(certificate).read_bytes())
    return hashlib.sha256(cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).digest()


class ProviderServer:
    """Bounded sequential service. An error never triggers a direct tool retry.

    The callback receives a decoded frame only AFTER mutual TLS, exact client
    certificate pin, ALPN, target URL and server key pin checks. The kernel's G7
    permit is verified by execd, not re-created by this business endpoint.
    """
    def __init__(self, *, address, context, client_pin, server_pin, urls, alpn, exchange):
        if (any(type(v) is not bytes or len(v) != 32 or not any(v) for v in (client_pin, server_pin))
            or type(urls) is not tuple or not 1 <= len(urls) <= 2
            or any(urlsplit(u).scheme != "https" or not urlsplit(u).hostname for u in urls)
            or not callable(exchange)):
            raise ValueError("explicit_provider_binding_required")
        self.context, self.client_pin, self.server_pin = context, client_pin, server_pin
        self.urls, self.alpn, self.exchange = urls, alpn, exchange
        self._stop, self._lock = threading.Event(), threading.Lock()
        self.connections = self.rejections = self.delivered = 0
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Sequential episodes may leave accepted connections in TIME_WAIT.
            # SO_REUSEPORT is deliberately not enabled; a live owner still wins.
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind(address)
            self.listener.listen(8)
            self.listener.settimeout(.2)
        except BaseException:
            self.listener.close()
            raise
        self.address = self.listener.getsockname()
        self._thread = threading.Thread(target=self._serve, name="savana-dojo-provider", daemon=True)

    def start(self):
        self._thread.start()
        return self

    def _serve(self):
        while not self._stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.connections += 1
            try:
                self._connection(raw)
            except Exception:
                self.rejections += 1  # no raw TLS/payload exception in public logs
            finally:
                raw.close()

    def _connection(self, raw):
        end = time.monotonic() + 5
        def remaining():
            left = end - time.monotonic()
            if left <= 0:
                raise TimeoutError("provider_deadline")
            return left
        raw.settimeout(remaining())
        with self.context.wrap_socket(raw, server_side=True) as tls:
            if (tls.selected_alpn_protocol() != self.alpn
                or hashlib.sha256(tls.getpeercert(binary_form=True)).digest() != self.client_pin):
                raise ValueError("unauthenticated_executor")
            def read(size):
                parts = bytearray()
                while len(parts) < size:
                    tls.settimeout(remaining())
                    part = tls.recv(size - len(parts))
                    if not part:
                        raise EOFError("provider_frame_truncated")
                    parts.extend(part)
                return bytes(parts)
            frame = read_frame(read)
            if frame.url not in self.urls or frame.pin != self.server_pin:
                raise ValueError("provider_target_mismatch")
            remaining()
            response = self.exchange(frame)
            if type(response) is not bytes or not 0 < len(response) <= 32768:
                raise ValueError("provider_response_size")
            tls.settimeout(remaining())
            tls.sendall(response)
            self.delivered += 1
            # rustls reads until EOF and requires TLS close_notify.
            try:
                tls.settimeout(remaining())
                plain = tls.unwrap()
                plain.close()
            except (OSError, ssl.SSLError, TimeoutError):
                pass

    def close(self):
        self._stop.set()
        self.listener.close()
        if self._thread.ident is not None:
            self._thread.join(6)
            if self._thread.is_alive():
                raise RuntimeError("provider_shutdown_uncertain")
