"""Bounded chunk framing for the trusted experiment channel, not authentication.

SSM's PTY is not a reliable carrier for single multi-megabyte JSON lines. Each
wire line here is below 2 KiB; sequence, size and digest must all match before
returning a message. Never skip a damaged frame or resynchronize past it.
"""
import base64
import hashlib
import json

CHUNK_BYTES = 1024
MAX_MESSAGE_BYTES = 2 * 1024 * 1024
MAX_LINE_BYTES = 2048
SERVER_PREFIX = b'SAVANA_DOJO_CHUNK_V2 '
CLIENT_PREFIX = b'SAVANA_REPLY_CHUNK_V2 '


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate_frame_key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('nonfinite_frame_value')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


class Encoder:
    def __init__(self, prefix):
        if prefix not in (SERVER_PREFIX, CLIENT_PREFIX):
            raise ValueError('invalid_channel_prefix')
        self.prefix = prefix
        self.sequence = 0

    def frames(self, value):
        if not isinstance(value, dict):
            raise ValueError('message_must_be_object')
        raw = canonical(value)
        if not 0 < len(raw) <= MAX_MESSAGE_BYTES:
            raise ValueError('message_size')
        seq = self.sequence
        self.sequence += 1  # A partially written message cannot be reissued.
        total = (len(raw) + CHUNK_BYTES - 1) // CHUNK_BYTES
        digest = hashlib.sha256(raw).hexdigest()
        for index in range(total):
            part = raw[index * CHUNK_BYTES:(index + 1) * CHUNK_BYTES]
            line = self.prefix + canonical(dict(seq=seq, part=index, total=total,
                size=len(raw), sha256=digest, data=base64.b64encode(part).decode())) + b'\n'
            if len(line) > MAX_LINE_BYTES:
                raise ValueError('wire_line_size')
            yield line

    def write(self, stream, value):
        for line in self.frames(value):
            remaining = memoryview(line)
            while remaining:
                count = stream.write(remaining)
                if count is None or count <= 0 or count > len(remaining):
                    raise OSError('channel_short_write')
                remaining = remaining[count:]
        stream.flush()


class Decoder:
    def __init__(self, prefix):
        if prefix not in (SERVER_PREFIX, CLIENT_PREFIX):
            raise ValueError('invalid_channel_prefix')
        self.prefix = prefix
        self.sequence = 0
        self.part = 0
        self.metadata = None
        self.buffer = bytearray()
        self.failed = False

    def feed_line(self, line):
        if self.failed:
            raise ValueError('channel_poisoned')
        try:
            return self._feed_line(line)
        except Exception:
            self.failed = True
            self.buffer.clear()
            raise

    def _feed_line(self, line):
        if not isinstance(line, bytes) or len(line) > MAX_LINE_BYTES or not line.endswith(b'\n'):
            raise ValueError('wire_line_size_or_termination')
        # Accept CRLF from a PTY, but never arbitrary prefixes or terminal text.
        line = line[:-1].removesuffix(b'\r')
        if not line.startswith(self.prefix):
            raise ValueError('wrong_channel')
        item = strict_json(line[len(self.prefix):])
        if not isinstance(item, dict) or set(item) != {'seq','part','total','size','sha256','data'}:
            raise ValueError('frame_fields')
        if any(type(item[k]) is not int for k in ('seq','part','total','size')):
            raise ValueError('frame_integer_type')
        if (item['seq'] != self.sequence or item['part'] != self.part
                or not 0 < item['size'] <= MAX_MESSAGE_BYTES
                or item['total'] != (item['size'] + CHUNK_BYTES - 1) // CHUNK_BYTES
                or not 0 <= item['part'] < item['total']):
            raise ValueError('frame_sequence_or_size')
        digest = item['sha256']
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('digest_shape')
        metadata = (item['size'], item['total'], digest)
        if self.metadata is not None and self.metadata != metadata:
            raise ValueError('frame_rebound')
        self.metadata = metadata
        if not isinstance(item['data'], str):
            raise ValueError('frame_data_type')
        part = base64.b64decode(item['data'], validate=True)
        if base64.b64encode(part).decode() != item['data']:
            raise ValueError('noncanonical_base64')
        expected = min(CHUNK_BYTES, item['size'] - self.part * CHUNK_BYTES)
        if len(part) != expected:
            raise ValueError('chunk_size')
        self.buffer.extend(part); self.part += 1
        if self.part != item['total']:
            return None
        raw = bytes(self.buffer)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('message_digest')
        value = strict_json(raw)
        if not isinstance(value, dict) or canonical(value) != raw:
            raise ValueError('noncanonical_message')
        self.sequence += 1; self.part = 0; self.metadata = None; self.buffer.clear()
        return value

    def finish(self):
        if self.failed or self.part:
            self.failed = True
            raise ValueError('incomplete_channel')

    def read(self, stream):
        while True:
            line = stream.readline(MAX_LINE_BYTES + 1)
            if not line:
                self.failed = True
                raise EOFError('message_not_received')
            value = self.feed_line(line)
            if value is not None:
                return value
