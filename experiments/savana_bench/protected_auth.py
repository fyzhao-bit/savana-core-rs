"""Interactive passkey bridge by default; optional disposable benchmark mode.

Two separated channels: root-owned Unix peer for the runner; loopback HTTP with
a fresh root-held bearer for a local administrator tunnel. No kernel IPC here.
An uncertain/expired request is never retried automatically or auto-approved.
Only the explicit --software-benchmark flag selects a separately enrolled
software fixture, which must never be described as human authentication.
"""
import hmac
import http.server
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import struct
import threading
import time

from .agentdojo_provider import canonical
from .protected_operator import receive, send, private_read, retain

SOCKET = '/run/savana-experiment-auth/owner.sock'
TOKEN = '/var/lib/savana-experiment-auth/browser.token'
ORIGIN = 'http://localhost:8766'
READY_WAIT_SECONDS = 900  # No kernel bootstrap/challenge exists during this wait.
LAUNCH_ID = re.compile(r'[A-Za-z0-9_-]{43}\Z')


class CeremonyQueue:
    def __init__(self):
        self.condition = threading.Condition()
        self.pending = None
        self.response = None
        self.deadline = None

    def exchange(self, request, timeout=115):
        if (type(request) is not dict or type(request.get('protocol_version')) is not int
                or request['protocol_version'] != 1 or request.get('type') not in (
                    'experiment.ready', 'approval.decide', 'webauthn.assert', 'webauthn.create')):
            raise ValueError('unsupported_auth_request')
        if request['type'] == 'experiment.ready':
            if (set(request) != {'protocol_version','type','launch_id'}
                    or type(request['launch_id']) is not str or not LAUNCH_ID.fullmatch(request['launch_id'])):
                raise ValueError('readiness_fields')
            timeout = min(timeout, READY_WAIT_SECONDS)
        elif request['type'] == 'approval.decide':
            if set(request) != {'protocol_version','type','approval_id','display','purpose','deadline_unix_ms'}:
                raise ValueError('approval_fields')
            timeout = min(timeout, (request['deadline_unix_ms']-time.time_ns()//1000000)/1000)
        elif set(request) != {'protocol_version','type','options_json'}:
            raise ValueError('ceremony_fields')
        if timeout <= 0: raise TimeoutError('expired_auth_request')
        with self.condition:
            if self.pending is not None: raise ValueError('single_ceremony_only')
            request_id = secrets.token_urlsafe(32)
            self.deadline = time.monotonic() + timeout
            self.pending = dict(id=request_id, request=request,
                expires_at_unix_ms=time.time_ns()//1000000 + int(timeout*1000))
            self.response = None
            try:
                if not self.condition.wait_for(lambda: self.response is not None, timeout):
                    print(json.dumps(dict(auth_event='request_expired',request_type=request['type'])),flush=True)
                    raise TimeoutError('authentication_not_confirmed')
                response = self.response
                if response.get('cancelled') is True:
                    print(json.dumps(dict(auth_event='cancellation_received',request_type=request['type'])),flush=True)
                    raise ValueError('authentication_cancelled')
                return response
            finally:
                self.pending = self.response = self.deadline = None

    def poll(self):
        with self.condition:
            return self.pending

    def complete(self, message):
        if (type(message) is not dict or set(message) != {'id','response'}
                or type(message['id']) is not str or type(message['response']) is not dict):
            raise ValueError('closed_auth_response')
        with self.condition:
            if (self.pending is None or time.monotonic() >= self.deadline
                    or not hmac.compare_digest(message['id'], self.pending['id']) or self.response is not None):
                raise ValueError('stale_auth_response')
            response, request = message['response'], self.pending['request']
            if response != {'cancelled': True}:
                kind = request['type']
                fields = {'protocol_version','type'}
                if kind == 'experiment.ready':
                    fields |= {'launch_id','start'}
                    if response.get('launch_id') != request['launch_id'] or type(response.get('start')) is not bool:
                        raise ValueError('readiness_identity')
                    expected = 'experiment.start'
                elif kind == 'approval.decide':
                    fields |= {'approval_id','approved'}
                    if response.get('approval_id') != request['approval_id'] or type(response.get('approved')) is not bool:
                        raise ValueError('approval_identity')
                    expected = 'approval.decision'
                else:
                    expected = 'webauthn.assertion' if kind == 'webauthn.assert' else 'webauthn.attestation'
                    fields |= ({'credential_id','authenticator_data','client_data_json','signature','user_handle'}
                        if kind == 'webauthn.assert' else {'credential_id','client_data_json','attestation_object'})
                    if any(type(response.get(k)) is not str for k in fields-{'protocol_version','type'}):
                        raise ValueError('binary_response_fields')
                if (set(response) != fields or type(response.get('protocol_version')) is not int
                        or response['protocol_version'] != 1 or response.get('type') != expected):
                    raise ValueError('auth_response_fields')
            self.response = response
            self.condition.notify_all()


def http_handler(queue, token):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def respond(self, status, value):
            data = canonical(value)
            self.send_response(status)
            self.send_header('Content-Type','application/json')
            self.send_header('Cache-Control','no-store')
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Length',str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def authorized(self):
            return (self.headers.get('Host') == 'localhost:8786'
                and hmac.compare_digest(self.headers.get('Authorization',''), 'Bearer '+token)
                and self.headers.get('Origin') == ORIGIN)
        def do_GET(self):
            if not self.authorized(): return self.respond(403, {'status':'denied'})
            if self.path != '/pending': return self.respond(404, {'status':'not_found'})
            self.respond(200, dict(pending=queue.poll()))
        def do_POST(self):
            if not self.authorized(): return self.respond(403, {'status':'denied'})
            try:
                if self.path not in ('/complete','/configure-model') or self.headers.get('Transfer-Encoding'):
                    raise ValueError('closed_route')
                size=int(self.headers['Content-Length'])
                if not 0 < size <= 262144: raise ValueError('frame_bound')
                value=json.loads(self.rfile.read(size))
                if self.path=='/configure-model':
                    if type(value) is not dict or set(value)!={'api_key'} or type(value['api_key']) is not str:
                        raise ValueError('closed_credential_input')
                    from .protected_admin import install_model_key
                    install_model_key(value['api_key'].encode('ascii'),transient=True)
                    del value
                else:queue.complete(value)
                self.respond(200, {'status':'received'})
            except Exception: self.respond(409, {'status':'not_confirmed'})
    return Handler


def serve_channel(channel, queue, issue_bootstrap, *, ready_timeout=READY_WAIT_SECONDS):
    """A browser click permits starting, never approves an input/task/action."""
    ready = False
    while True:
        request = receive(channel)
        if not ready:
            if type(request) is not dict or request.get('type') != 'experiment.ready':
                raise ValueError('browser_readiness_required')
            response = queue.exchange(request, timeout=ready_timeout)
            if response.get('start') is not True:
                raise ValueError('experiment_start_declined')
            send(channel, response)
            ready = True
        elif request == {'protocol_version':1,'type':'session.bootstrap'}:
            from .benchmark_identity import SoftwareCeremonyQueue
            token=(queue.bootstrap(issue_bootstrap) if isinstance(queue,SoftwareCeremonyQueue)
                else issue_bootstrap())
            send(channel, dict(protocol_version=1,type='session.bootstrap_token',
                control_plane_token=token))
        else:
            if type(request) is dict and request.get('type') == 'experiment.ready':
                raise ValueError('readiness_already_consumed')
            send(channel, queue.exchange(request))


def main(argv=()):
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--software-benchmark',action='store_true',
        help='Disposable experiment ONLY: simulated UP/UV, no human authentication assurance')
    args=parser.parse_args(argv)
    if os.geteuid()!=0 or os.environ.get('LISTEN_PID')!=str(os.getpid()) or os.environ.get('LISTEN_FDS')!='1':
        raise ValueError('root_socket_activation_required')
    if os.environ.get('LISTEN_FDNAMES')!='savana-experiment-auth': raise ValueError('auth_listener')
    # Reuse only this service's private token; it is not an enrollment or kernel capability.
    if not Path(TOKEN).exists(): retain(TOKEN,secrets.token_urlsafe(32).encode())
    token=private_read(TOKEN,43).decode('ascii')
    if len(token)!=43: raise ValueError('private_auth_token')
    if args.software_benchmark:
        from .benchmark_identity import SoftwareCeremonyQueue
        queue=SoftwareCeremonyQueue()
    else: queue=CeremonyQueue()
    http_service=http.server.ThreadingHTTPServer(('127.0.0.1',8786),http_handler(queue,token))
    threading.Thread(target=http_service.serve_forever,daemon=True).start()
    uid=pwd.getpwnam('savana-experiment').pw_uid
    from savana.owner_control import issue_bootstrap
    with socket.socket(fileno=os.dup(3)) as listener:
        if listener.family!=socket.AF_UNIX or listener.getsockname()!=SOCKET or not listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN):
            raise ValueError('auth_listener')
        while True:
            channel,_=listener.accept()
            with channel:
                channel.settimeout(180)
                try:
                    pid,peer,gid=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    if pid<=0 or peer!=uid or gid!=uid: raise ValueError('experiment_peer')
                    serve_channel(channel, queue, issue_bootstrap)
                except Exception:
                    # EOF, uncertainty, or user cancellation closes this authentication channel.
                    pass


if __name__=='__main__': main(None)
