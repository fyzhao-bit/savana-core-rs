import base64
import io
import json
import subprocess
import sys
import unittest

from savana_bench.framed_channel import (
    CLIENT_PREFIX, SERVER_PREFIX, CHUNK_BYTES, MAX_LINE_BYTES,
    MAX_MESSAGE_BYTES, Encoder, Decoder, canonical,
)


class FrameTests(unittest.TestCase):
    def frames(self, value=None):
        return list(Encoder(SERVER_PREFIX).frames(value or {'payload':'x'*6000}))

    def mutate(self, line, **fields):
        item=json.loads(line[len(SERVER_PREFIX):]); item.update(fields)
        return SERVER_PREFIX + canonical(item) + b'\n'

    def test_large_unicode_bidirectional_roundtrip(self):
        for prefix in (SERVER_PREFIX,CLIENT_PREFIX):
            encoder=Encoder(prefix); decoder=Decoder(prefix)
            for data in ({'payload':'秘密\n'*100000}, {'role':'assistant','tool_calls':[{'args':'y'*9000}]}, {}):
                lines=list(encoder.frames(data))
                self.assertTrue(all(len(line)<=MAX_LINE_BYTES for line in lines))
                self.assertEqual(decoder.read(io.BytesIO(b''.join(lines))),data)
            decoder.finish()

    def test_pty_crlf(self):
        lines=[x[:-1]+b'\r\n' for x in self.frames()]
        self.assertEqual(Decoder(SERVER_PREFIX).read(io.BytesIO(b''.join(lines))),{'payload':'x'*6000})

    def test_missing_duplicate_reordered_parts_poison(self):
        lines=self.frames()
        for broken in ([lines[1]], [lines[0],lines[0]], [lines[0],lines[2]]):
            decoder=Decoder(SERVER_PREFIX)
            with self.assertRaises(ValueError):
                for line in broken:decoder.feed_line(line)
            with self.assertRaisesRegex(ValueError,'poisoned'):decoder.feed_line(lines[0])

    def test_corruption_rebound_boolean_and_bounds(self):
        lines=self.frames()
        broken=[self.mutate(lines[0],seq=True), self.mutate(lines[0],size=MAX_MESSAGE_BYTES+1),
                self.mutate(lines[0],total=0), self.mutate(lines[0],sha256='z'*64),
                self.mutate(lines[0],data=base64.b64encode(b'x').decode()), b'x'*MAX_LINE_BYTES+b'\n']
        for line in broken:
            with self.assertRaises(ValueError):Decoder(SERVER_PREFIX).feed_line(line)
        decoder=Decoder(SERVER_PREFIX);decoder.feed_line(lines[0])
        with self.assertRaises(ValueError):decoder.feed_line(self.mutate(lines[1],sha256='1'*64))

    def test_message_digest_checked_before_delivery(self):
        lines=self.frames({'payload':'a'})
        with self.assertRaisesRegex(ValueError,'message_digest'):
            Decoder(SERVER_PREFIX).feed_line(self.mutate(lines[0],sha256='0'*64))

    def test_incomplete_eof_and_wrong_direction(self):
        decoder=Decoder(SERVER_PREFIX);decoder.feed_line(self.frames()[0])
        with self.assertRaises(ValueError):decoder.finish()
        with self.assertRaises(EOFError):Decoder(SERVER_PREFIX).read(io.BytesIO())
        with self.assertRaises(ValueError):Decoder(CLIENT_PREFIX).feed_line(self.frames()[0])

    def test_no_terminal_prefix_resynchronization(self):
        with self.assertRaises(ValueError):Decoder(SERVER_PREFIX).feed_line(b'echo ^J'+self.frames()[0])

    def test_duplicate_metadata_and_nonfinite_rejected(self):
        line=self.frames()[0]
        for value in (line.replace(b'"seq":0',b'"seq":0,"seq":0'),line.replace(b'"seq":0',b'"seq":NaN')):
            with self.assertRaises(ValueError):Decoder(SERVER_PREFIX).feed_line(value)

    def test_sender_rejects_oversize(self):
        with self.assertRaises(ValueError):list(Encoder(SERVER_PREFIX).frames({'payload':'x'*MAX_MESSAGE_BYTES}))

    def test_sender_rejects_nonobject_and_handles_partial_writes(self):
        with self.assertRaises(ValueError):list(Encoder(SERVER_PREFIX).frames([]))
        class Partial(io.BytesIO):
            def write(self, data):
                return super().write(data[:17])
        stream=Partial(); Encoder(CLIENT_PREFIX).write(stream,{'large':'x'*8000})
        self.assertEqual(Decoder(CLIENT_PREFIX).read(io.BytesIO(stream.getvalue())),{'large':'x'*8000})
        class Failed(io.BytesIO):
            def write(self, data):return 0
        with self.assertRaises(OSError):Encoder(CLIENT_PREFIX).write(Failed(),{'a':1})

    def test_real_bidirectional_subprocess_large_messages(self):
        # Exercises both streams with payloads larger than pipe/PTY line buffers.
        # This is a synthetic transport regression, never an AgentDojo score.
        program='''
import sys
from savana_bench.framed_channel import *
sender=Encoder(SERVER_PREFIX)
sender.write(sys.stdout.buffer, {'kind':'request','payload':'public synthetic '*40000})
reply=Decoder(CLIENT_PREFIX).read(sys.stdin.buffer)
assert reply=={'kind':'reply','payload':'synthetic result '*20000}
sender.write(sys.stdout.buffer, {'kind':'done'})
'''
        child=subprocess.Popen([sys.executable,'-c',program],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            decoder=Decoder(SERVER_PREFIX)
            self.assertEqual(decoder.read(child.stdout),{'kind':'request','payload':'public synthetic '*40000})
            Encoder(CLIENT_PREFIX).write(child.stdin,{'kind':'reply','payload':'synthetic result '*20000})
            self.assertEqual(decoder.read(child.stdout),{'kind':'done'})
            self.assertEqual(child.wait(timeout=10),0)
            decoder.finish()
        finally:
            if child.poll() is None:child.kill(); child.wait(timeout=10)
            child.stdin.close(); child.stdout.close(); child.stderr.close()


if __name__=='__main__':unittest.main()
