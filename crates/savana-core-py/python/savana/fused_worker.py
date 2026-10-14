"""v0.4 model worker endpoint. Never an execution/approval/egress authority.

Only a kernel-authenticated, already released ModelView is accepted. TLS must
terminate here (not at a plaintext proxy). The model callback proposes a closed
choice; Rust remains responsible for job/view, policy, root and execution checks.
No tool runtime, private task input, state store or signing key is exposed here.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import time
from dataclasses import dataclass

PATH = '/savana.fused.v04/exchange'
MAX_VIEW = 16384
MAX_REPLY = 16384
FIELDS = ('schema','job','role','model_profile','deadline','mode','public_view',
          'template_ids','question_codes','suggested_templates','suggested_questions')


def inherited_listener(fd, path):
    """Duplicate a deployment-owned Unix listener; never bind/unlink a path.

    The kernel uses Unix TLS, not TCP. The service manager retains ownership of
    the original descriptor. A listening socket is not proof of kernel identity:
    every accepted connection still passes the pinned mutual-TLS checks below.
    """
    if (type(fd) is not int or fd < 3 or type(path) is not str
            or not path.startswith('/') or len(os.fsencode(path)) > 100
            or any(p in ('', '.', '..') for p in path.split('/')[1:])):
        raise ValueError('model_listener_binding')
    current = Path(path)
    meta = current.lstat()
    if (not stat.S_ISSOCK(meta.st_mode) or meta.st_uid not in (0, os.geteuid())
            or meta.st_mode & 0o007):
        raise ValueError('model_listener_permissions')
    for parent in current.parents:
        m = parent.lstat()
        if (not stat.S_ISDIR(m.st_mode) or m.st_uid not in (0, os.geteuid())
                or m.st_mode & 0o022):
            raise ValueError('model_listener_parent')
    duplicate = None
    raw = os.dup(fd)
    try:
        duplicate = socket.socket(fileno=raw)
        if (duplicate.family != socket.AF_UNIX
                or duplicate.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
                or duplicate.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
                or duplicate.getsockname() != path):
            raise ValueError('model_listener_binding')
        return duplicate
    except BaseException:
        if duplicate is None:
            os.close(raw)
        else:
            duplicate.close()
        raise


def _json(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()


def _parse(raw):
    def pairs(items):
        result = {}
        for key,value in items:
            if key in result: raise ValueError('duplicate_field')
            result[key]=value
        return result
    def invalid(_): raise ValueError('nonfinite')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def _integers(values, limit, *, size=None):
    return (type(values) is list and (size is None or len(values)==size)
            and all(type(v) is int and 0<=v<=limit for v in values))


@dataclass(frozen=True, repr=False)
class ModelJob:
    """A released model view, not a capability. No task/root/private value ID."""
    raw: bytes
    view: dict
    commitment: bytes
    deadline_ms: int

    @classmethod
    def decode(cls, raw):
        if not isinstance(raw, bytes) or not 0<len(raw)<=MAX_VIEW: raise ValueError('view_size')
        v=_parse(raw)
        if not isinstance(v,dict) or tuple(v)!=FIELDS or _json(v)!=raw: raise ValueError('view_shape')
        if (type(v['schema']) is not int or v['schema']!=1
                or not _integers(v['job'],255,size=16) or not any(v['job'])
                or v['role'] not in ('advisor','planner')
                or type(v['model_profile']) is not int or not 1<=v['model_profile']<=65535
                or not _integers(v['deadline'],255,size=8) or not any(v['deadline'])
                or v['mode'] not in ('registered_template_v04','structural_order_v04')
                or not _integers(v['public_view'],255) or len(v['public_view'])>4096):
            raise ValueError('view_values')
        bytes(v['public_view']).decode('utf-8',errors='strict')
        for name in FIELDS[8:]:
            if not _integers(v[name],65535) or len(v[name])>64: raise ValueError('view_list')
        domain=b'SAVANA_FUSED_MODEL_VIEW_V04\0'
        digest=hashlib.sha256(len(domain).to_bytes(8,'big')+domain+len(raw).to_bytes(8,'big')+raw).digest()
        # Unix ms as 8 big-endian bytes: a decimal would trip the G3 PII gate.
        return cls(raw,v,digest,int.from_bytes(bytes(v['deadline']),'big'))

    def encode_proposal(self, proposed):
        # This is syntax/binding only, never an authorization decision. Rust
        # checks membership, ordering, frozen prefix and all downstream gates.
        if not isinstance(proposed,dict): raise ValueError('proposal_shape')
        bound=dict(schema=1,job=self.view['job'],view=list(self.commitment))
        if self.view['role']=='advisor':
            if set(proposed)!={'templates','questions'}: raise ValueError('advice_fields')
            if any(not _integers(proposed[k],65535) or len(proposed[k])>64 for k in proposed):
                raise ValueError('advice_values')
            bound.update(templates=proposed['templates'],questions=proposed['questions'])
        else:
            if set(proposed)!={'choice'} or not isinstance(proposed['choice'],dict):raise ValueError('choice_fields')
            c=proposed['choice']
            if c.get('kind')=='registered_template' and set(c)=={'kind','template'}:
                if type(c['template']) is not int or not 1<=c['template']<=65535:raise ValueError('template')
                choice=dict(kind='registered_template',template=c['template'])
            elif c.get('kind')=='structural_order' and set(c)=={'kind','order'}:
                if not _integers(c['order'],65535) or not 0<len(c['order'])<=64:raise ValueError('order')
                choice=dict(kind='structural_order',order=c['order'])
            else:raise ValueError('choice_kind')
            bound['choice']=choice
        raw=_json(bound)
        if len(raw)>MAX_REPLY:raise ValueError('proposal_size')
        return raw


def cbor_bytes(value):
    n=len(value)
    if n<24:return bytes([0x40+n])+value
    if n<256:return b'\x58'+bytes([n])+value
    if n<65536:return b'\x59'+n.to_bytes(2,'big')+value
    raise ValueError('cbor_size')


def decode_cbor_bytes(raw, maximum):
    if not raw:raise ValueError('empty_cbor')
    first=raw[0]
    if 0x40<=first<0x58:size=first-0x40;offset=1
    elif first==0x58 and len(raw)>=2:size=raw[1];offset=2
    elif first==0x59 and len(raw)>=3:size=int.from_bytes(raw[1:3],'big');offset=3
    else:raise ValueError('cbor_shape')
    value=raw[offset:]
    if not 0<size<=maximum or len(value)!=size or cbor_bytes(value)!=raw:raise ValueError('cbor_size_or_canonical')
    return value


def server_context(*, certificate, private_key, client_ca):
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version=ssl.TLSVersion.TLSv1_3
    ctx.verify_mode=ssl.CERT_REQUIRED
    ctx.load_cert_chain(certificate,private_key)
    ctx.load_verify_locations(cafile=client_ca)
    ctx.set_alpn_protocols(['http/1.1'])
    ctx.num_tickets=0
    return ctx


def serve_connection(raw_socket, *, context, client_certificate_sha256, propose, clock=time.monotonic):
    """One mTLS connection, one callback, one response; no retry or logging.

    `propose(ModelJob, absolute_monotonic_deadline)` must obey the deadline and
    must not execute tools. A late callback result is never sent. Kernel also
    enforces its own absolute deadline independently of this process.
    The socket's ownership transfers here and it is always closed.
    """
    tls=None
    try:
        if len(client_certificate_sha256)!=32:raise ValueError('client_pin')
        end=clock()+5
        def remaining():
            left=end-clock()
            if left<=0:raise TimeoutError('worker_deadline')
            return left
        raw_socket.settimeout(remaining())
        tls=context.wrap_socket(raw_socket,server_side=True,do_handshake_on_connect=False)
        tls.do_handshake()
        if (tls.selected_alpn_protocol()!='http/1.1'
                or hashlib.sha256(tls.getpeercert(binary_form=True)).digest()!=client_certificate_sha256):
            raise ValueError('client_binding')
        def read(count):
            out=bytearray()
            while len(out)<count:
                tls.settimeout(remaining());part=tls.recv(count-len(out))
                if not part:raise EOFError('request_truncated')
                out.extend(part)
            return bytes(out)
        header=bytearray()
        while not header.endswith(b'\r\n\r\n'):
            if len(header)>=4096:raise ValueError('header_bound')
            header.extend(read(1))
        lines=bytes(header).decode('ascii').split('\r\n')
        if lines[0]!=f'POST {PATH} HTTP/1.1':raise ValueError('request_path')
        fields={}
        for line in lines[1:-2]:
            name,value=line.split(':',1);name=name.lower()
            if name in fields:raise ValueError('duplicate_header')
            fields[name]=value.strip()
        if (set(fields)!={'host','content-type','accept','content-length','connection'}
                or fields['content-type']!='application/cbor' or fields['accept']!='application/cbor'
                or fields['connection'].lower()!='close' or not fields['content-length'].isascii()
                or not fields['content-length'].isdecimal()):raise ValueError('request_headers')
        size=int(fields['content-length'])
        if not 0<size<=MAX_VIEW+3:raise ValueError('request_size')
        job=ModelJob.decode(decode_cbor_bytes(read(size),MAX_VIEW))
        if job.deadline_ms<=int(time.time()*1000):raise TimeoutError('view_expired')
        end=min(end,clock()+(job.deadline_ms/1000-time.time()))
        remaining()
        response=job.encode_proposal(propose(job,end))
        remaining()
        body=cbor_bytes(response)
        reply=(f'HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n').encode()+body
        tls.settimeout(remaining());tls.sendall(reply)
        # Sends close_notify. Peer may close immediately after receiving it.
        try:
            tls.settimeout(remaining());plain=tls.unwrap();plain.close()
        except (OSError,ssl.SSLError,TimeoutError):pass
    finally:
        if tls is not None:tls.close()
        raw_socket.close()
