"""Single-connection interoperability probe using repository TEST keys only."""
import base64
import hashlib
import importlib.util
from pathlib import Path
import socket
import sys

root=Path(__file__).resolve().parents[3]
spec=importlib.util.spec_from_file_location('probe_worker',root/'crates/savana-core-py/python/savana/fused_worker.py')
worker=importlib.util.module_from_spec(spec);sys.modules[spec.name]=worker;spec.loader.exec_module(worker)
directory=Path(sys.argv[1])
values=dict(line.split('=',1) for line in (root/'crates/savana-execd/tests/fixtures/provider-tls-v2.hex').read_text().splitlines() if '=' in line)
def pem(name,kind):
    path=directory/name
    with path.open('x') as f:
        f.write(f'-----BEGIN {kind}-----\n'+base64.encodebytes(bytes.fromhex(values[name])).decode()+f'-----END {kind}-----\n')
    path.chmod(0o600)
    return str(path)
ctx=worker.server_context(certificate=pem('server_cert','CERTIFICATE'),private_key=pem('server_key','PRIVATE KEY'),client_ca=pem('ca_cert','CERTIFICATE'))
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
    server.bind(str(directory/'python.sock'));server.settimeout(10);server.listen(1)
    print('READY',flush=True)
    connection,_=server.accept()
    worker.serve_connection(connection,context=ctx,
        client_certificate_sha256=hashlib.sha256(bytes.fromhex(values['client_cert'])).digest(),
        propose=lambda job,deadline: {'choice':{'kind':'registered_template','template':1}})
