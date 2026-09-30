"""SDK worker protocol tests; no paid model calls or AgentDojo scores."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest

ROOT=Path(__file__).resolve().parents[2]
SOCKET_DIR=Path(os.environ.get('SAVANA_TEST_SOCKET_DIRECTORY', str(ROOT)))
spec=importlib.util.spec_from_file_location('savana_fused_worker_under_test',ROOT/'crates/savana-core-py/python/savana/fused_worker.py')
worker=importlib.util.module_from_spec(spec);sys.modules[spec.name]=worker;spec.loader.exec_module(worker)


def view(**changes):
    value=dict(schema=1,job=[1]*16,role='planner',model_profile=1,deadline=int(time.time()*1000)+10000,
               mode='registered_template_v04',public_view=list(b'public synthetic task'),template_ids=[1,2],
               question_codes=[],suggested_templates=[],suggested_questions=[])
    value.update(changes);return worker._json(value)


class WorkerTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'linux', 'Linux SO_ACCEPTCONN listener admission')
    def test_inherited_unix_listener_is_duplicated_not_rebound(self):
        # Use protected ancestors, not world-writable /tmp. Production requires
        # the service-manager-owned /run tree and must not relax that check.
        with tempfile.TemporaryDirectory(prefix='.fd-', dir=SOCKET_DIR) as directory:
            path = str(Path(directory) / 'model.sock')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as original:
                original.bind(path)
                os.chmod(path, 0o660)
                original.listen(1)
                duplicate = worker.inherited_listener(original.fileno(), path)
                self.assertNotEqual(duplicate.fileno(), original.fileno())
                duplicate.close()
                self.assertTrue(Path(path).exists())
                self.assertEqual(original.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN), 1)
                os.chmod(path, 0o666)
                with self.assertRaises(ValueError):
                    worker.inherited_listener(original.fileno(), path)
                os.chmod(path, 0o660)
                os.chmod(directory, 0o770)
                with self.assertRaises(ValueError):
                    worker.inherited_listener(original.fileno(), path)
                os.chmod(directory, 0o700)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux SO_ACCEPTCONN listener admission')
    def test_nonlistener_wrong_path_and_tcp_never_accepted(self):
        with tempfile.TemporaryDirectory(prefix='.fd-', dir=SOCKET_DIR) as directory:
            path = str(Path(directory) / 'model.sock')
            other = str(Path(directory) / 'other.sock')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as original:
                original.bind(path)
                os.chmod(path, 0o600)
                with self.assertRaises(ValueError):
                    worker.inherited_listener(original.fileno(), path)
                original.listen(1)
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as second:
                    second.bind(other)
                    os.chmod(other, 0o600)
                    second.listen(1)
                    with self.assertRaises(ValueError):
                        worker.inherited_listener(original.fileno(), other)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
                    tcp.bind(('127.0.0.1', 0))
                    tcp.listen(1)
                    with self.assertRaises(ValueError):
                        worker.inherited_listener(tcp.fileno(), path)
                for bad in (None, True, -1, 0, 1, 2):
                    with self.assertRaises(ValueError):
                        worker.inherited_listener(bad, path)

    def test_closed_job_and_proposal_binding(self):
        raw=view();job=worker.ModelJob.decode(raw)
        reply=json.loads(job.encode_proposal({'choice':{'template':2,'kind':'registered_template'}}))
        domain=b'SAVANA_FUSED_MODEL_VIEW_V04\0'
        digest=hashlib.sha256(len(domain).to_bytes(8,'big')+domain+len(raw).to_bytes(8,'big')+raw).digest()
        self.assertEqual(reply,dict(schema=1,job=[1]*16,view=list(digest),choice=dict(kind='registered_template',template=2)))
        self.assertNotIn('synthetic',repr(job))
        advisor=worker.ModelJob.decode(view(role='advisor'))
        self.assertEqual(json.loads(advisor.encode_proposal(dict(templates=[2],questions=[])))['templates'],[2])

    def test_invalid_input_and_model_generated_authority_are_rejected(self):
        for raw in (view(job=[True]*16),view(schema=True),view(public_view=[256]),view(model_profile=0),
                    view(root=[1]*32),view()+b' ',view().replace(b'"schema":1',b'"schema":1,"schema":1'),view(role='executor')):
            with self.assertRaises(ValueError):worker.ModelJob.decode(raw)
        job=worker.ModelJob.decode(view())
        for proposed in ({'allowed':True},{'choice':{'kind':'registered_template','template':True}},
                         {'choice':{'kind':'execute','command':'send_email'}},
                         {'choice':{'kind':'registered_template','template':1},'job':[9]*16}):
            with self.assertRaises(ValueError):job.encode_proposal(proposed)

    def test_binding_changes_with_each_view_and_no_authority_is_created(self):
        a=worker.ModelJob.decode(view(deadline=10000));b=worker.ModelJob.decode(view(deadline=10001))
        self.assertNotEqual(a.commitment,b.commitment)
        # Syntax bridge does not claim to authorize template 9: Rust rejects it.
        self.assertEqual(json.loads(a.encode_proposal({'choice':{'kind':'registered_template','template':9}}))['choice']['template'],9)

    def test_cbor_byte_string_is_bounded_and_canonical(self):
        for size in (1,23,24,255,256,16384):
            value=b'x'*size
            self.assertEqual(worker.decode_cbor_bytes(worker.cbor_bytes(value),16384),value)
        for raw in (b'',b'\x40',b'\x58\x01x',b'\x41xx',b'\x5f',worker.cbor_bytes(b'x'*16385)):
            with self.assertRaises(ValueError):worker.decode_cbor_bytes(raw,16384)

    def tls_roundtrip(self, *, wrong_pin=False, expired=False, malformed=False):
        values=dict(line.split('=',1) for line in (ROOT/'crates/savana-execd/tests/fixtures/provider-tls-v2.hex').read_text().splitlines() if '=' in line)
        def der(name):return bytes.fromhex(values[name])
        with tempfile.TemporaryDirectory(prefix='savana-worker-tls-') as directory:
            def pem(name,kind):
                path=Path(directory)/name
                path.write_text(f'-----BEGIN {kind}-----\n'+base64.encodebytes(der(name)).decode()+f'-----END {kind}-----\n')
                path.chmod(0o600);return str(path)
            ca=pem('ca_cert','CERTIFICATE');server_cert=pem('server_cert','CERTIFICATE');server_key=pem('server_key','PRIVATE KEY')
            client_cert=pem('client_cert','CERTIFICATE');client_key=pem('client_key','PRIVATE KEY')
            server_context=worker.server_context(certificate=server_cert,private_key=server_key,client_ca=ca)
            ctx=ssl.create_default_context(cafile=ca);ctx.minimum_version=ssl.TLSVersion.TLSv1_3
            ctx.load_cert_chain(client_cert,client_key);ctx.set_alpn_protocols(['http/1.1'])
            a,b=socket.socketpair();calls=[];errors=[]
            def propose(job,deadline):
                calls.append(job);self.assertGreater(deadline,time.monotonic())
                return {'choice':{'kind':'registered_template','template':1}}
            def serve():
                try:worker.serve_connection(b,context=server_context,client_certificate_sha256=(b'0'*32 if wrong_pin else hashlib.sha256(der('client_cert')).digest()),propose=propose)
                except Exception as error:errors.append(type(error).__name__)
            thread=threading.Thread(target=serve);thread.start()
            try:
                a.settimeout(2)
                with ctx.wrap_socket(a,server_hostname='provider.example') as tls:
                    body=worker.cbor_bytes(view(deadline=1) if expired else view())
                    extra=b'Content-Length: 1\r\n' if malformed else b''
                    header=(f'POST {worker.PATH} HTTP/1.1\r\nHost: provider.example\r\nContent-Type: application/cbor\r\nAccept: application/cbor\r\nContent-Length: {len(body)}\r\nConnection: close\r\n').encode()+extra+b'\r\n'
                    try:
                        tls.sendall(header+body);reply=b''
                        while True:
                            chunk=tls.recv(4096)
                            if not chunk:break
                            reply+=chunk
                        if not (wrong_pin or expired or malformed):
                            h,payload=reply.split(b'\r\n\r\n',1)
                            self.assertTrue(h.startswith(b'HTTP/1.1 200 OK'))
                            result=json.loads(worker.decode_cbor_bytes(payload,16384))
                            self.assertEqual(result['choice'],dict(kind='registered_template',template=1))
                            plain=tls.unwrap();plain.close()
                    except (OSError,ssl.SSLError):
                        if not (wrong_pin or expired or malformed):raise
            finally:
                a.close();thread.join(timeout=6);self.assertFalse(thread.is_alive())
            if wrong_pin or expired or malformed:self.assertEqual(calls,[]);self.assertTrue(errors)
            else:self.assertEqual(len(calls),1);self.assertEqual(errors,[])

    def test_real_mtls_serves_one_bound_proposal(self):self.tls_roundtrip()
    def test_wrong_client_certificate_pin_never_calls_model(self):self.tls_roundtrip(wrong_pin=True)
    def test_expired_view_never_calls_model(self):self.tls_roundtrip(expired=True)
    def test_duplicate_http_header_never_calls_model(self):self.tls_roundtrip(malformed=True)


if __name__=='__main__':unittest.main()
