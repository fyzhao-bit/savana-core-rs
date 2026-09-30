"""Independent, root-owned finite-calendar provisioning through Python SDK.

Not a general signing oracle. Only the clean reviewed catalog may be compiled;
the native kernel obtains inputs from consented ingress and supplies the recipe.
This service never performs WebAuthn, supplies user consent, calls a model/tool,
or reads kernel state. Unknown replies are retried with identical signed bytes.
"""
import asyncio
import hashlib
import json
import os
from pathlib import Path
import pwd
import socket
import stat
import struct
import time

from .agentdojo_provider import canonical
from .agentdojo_tasks import _TASKS, prepare_draft
from .protected_endpoint import digest32

SOCKET = '/run/savana-experiment-operator/operator.sock'
STATE = '/var/lib/savana-experiment-operator'
MAX = 262144


def read_exact(channel, size):
    value = bytearray()
    while len(value) < size:
        part = channel.recv(size-len(value))
        if not part: raise EOFError('operator_closed')
        value.extend(part)
    return bytes(value)


def receive(channel):
    size = int.from_bytes(read_exact(channel,4),'big')
    if not 0 < size <= MAX: raise ValueError('operator_frame_bound')
    def pairs(items):
        result={}
        for k,v in items:
            if k in result: raise ValueError('duplicate_operator_field')
            result[k]=v
        return result
    return json.loads(read_exact(channel,size),object_pairs_hook=pairs)


def send(channel, value):
    data=canonical(value)
    if len(data)>MAX: raise ValueError('operator_reply_bound')
    channel.sendall(len(data).to_bytes(4,'big')+data)


class OperatorClient:
    """Out-of-band operator RPC, never a kernel IPC transport."""
    def __init__(self, path=SOCKET):
        if path != SOCKET: raise ValueError('closed_operator_path')
        self.path=path

    def exchange(self, request):
        if os.uname().sysname != 'Linux': raise ValueError('linux_operator_required')
        for path in (Path(self.path), *Path(self.path).parents):
            meta=path.lstat()
            leaf=str(path)==self.path
            if (meta.st_uid!=0 or meta.st_mode & (0o007 if leaf else 0o022)
                or not (stat.S_ISSOCK(meta.st_mode) if leaf else stat.S_ISDIR(meta.st_mode))):
                raise ValueError('trusted_operator_path_required')
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
            channel.settimeout(125)
            channel.connect(self.path)
            pid,uid,gid=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if pid<=0 or uid!=0 or gid!=0: raise ValueError('operator_peer')
            send(channel,request)
            result=receive(channel)
        if type(result) is not dict or set(result)!={'status','result'} or result['status']!='ready':
            raise RuntimeError('operator_not_confirmed_preserve_task')
        return result['result']


def private_read(path, maximum=MAX):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        m=os.fstat(fd)
        if not stat.S_ISREG(m.st_mode) or m.st_uid!=os.geteuid() or m.st_mode&0o077 or m.st_size>maximum:
            raise ValueError('private_operator_file')
        data=os.read(fd,maximum+1)
        if len(data)>maximum: raise ValueError('operator_file_bound')
        return data
    finally: os.close(fd)


def retain(path, data):
    """Exclusive write-ahead. Existing bytes must match; never truncate/reset."""
    try: fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    except FileExistsError:
        if private_read(path)!=data: raise ValueError('operator_request_rebinding')
        return
    try:
        pending=memoryview(data)
        while pending:
            n=os.write(fd,pending)
            if n<=0: raise OSError('operator_journal_write')
            pending=pending[n:]
        os.fsync(fd)
    finally: os.close(fd)
    fd=os.open(Path(path).parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


class FiniteOperator:
    def __init__(self, deployment, signing_key, directory):
        self.deployment,self.key,self.directory=deployment,signing_key,Path(directory)

    def _submit(self, directory, name, command, *, wait=False):
        from savana.managed_admin import prepare_artifact, submit_signed
        artifact=prepare_artifact('command',canonical(command))
        raw=artifact.canonical_bytes()
        signature=self.key.sign(artifact.signing_digest())
        retain(directory/(name+'.json'),canonical(dict(command=list(raw),signature=list(signature))))
        deadline=time.monotonic()+(115 if wait else 0)
        while True:
            try:
                receipt=asyncio.run(submit_signed(raw,signature))
                document=json.loads(receipt.private_json())
                retain(directory/(name+'.receipt.json'),canonical(document))
                return document['result']
            except Exception:
                if time.monotonic()>=deadline: raise
                # Exact request replay only; no new root, run or input pin.
                time.sleep(.5)

    def compile(self, request):
        if set(request)!={'kind','contract','command'} or request['kind']!='compile':
            raise ValueError('closed_compile_request')
        contract=next((c for c in _TASKS if c.task_id==request['contract']),None)
        if contract is None: raise ValueError('unreviewed_contract')
        command=request['command']
        if set(command)!={'schema','installation','store','request','not_before','expires_at','operation'}:
            raise ValueError('closed_command')
        d=self.deployment
        if (command['schema']!=1 or command['installation']!=list(digest32(d['installation']))
            or command['store']!=list(digest32(d['store']))): raise ValueError('deployment_mismatch')
        op=command['operation']
        if set(op)!={'kind','task','draft'} or op['kind']!='compile_planning': raise ValueError('compile_only')
        draft=op['draft']
        task=bytes(op['task']);root=bytes(draft['root']);turn=bytes(draft['final_release']['turn'])
        if turn!=digest32(d['application_turn']): raise ValueError('application_turn_mismatch')
        if len(task)!=32 or not any(task) or type(command['not_before']) is not int or type(command['expires_at']) is not int:
            raise ValueError('task_binding')
        directory=self.directory/task.hex()
        # One canonical plan per task; a retry cannot create a fresh budget.
        if not directory.exists(): directory.mkdir(mode=0o700)
        meta=directory.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid!=os.geteuid() or meta.st_mode&0o077:
            raise ValueError('private_task_journal')
        if not (directory/'compile.json').exists():
            now=time.time_ns()//1_000_000
            if not now-300000<=command['not_before']<=now<command['expires_at']<=now+300000:
                raise ValueError('bounded_fresh_task')
        expected=prepare_draft(contract,task=task,root=root,observer=bytes(draft['observer_scope']),
            tool_descriptor=digest32(d['descriptors'][contract.tool]),
            release_descriptor=digest32(d['descriptors']['savana.final_result_release']),application_turn=turn,
            planner=digest32(d['planner']),model_profile=1,
            not_before=command['not_before'],expires_at=command['expires_at'])['planning_draft']
        if draft!=expected: raise ValueError('not_the_reviewed_finite_plan')
        retain(directory/'request.json',canonical(request))
        result=self._submit(directory,'compile',command)
        if result['kind']!='planning_enrolled' or result['task']!=list(task): raise ValueError('compile_receipt')
        return dict(task_id=task.hex(),profile=bytes(result['profile']).hex())

    def prepare(self, request):
        if set(request)!={'kind','task_id'} or request['kind']!='prepare': raise ValueError('closed_prepare_request')
        task=digest32(request['task_id']);directory=self.directory/task.hex()
        compiled=json.loads(private_read(directory/'request.json'))['command']
        root=compiled['operation']['draft']['root']
        command={**compiled,'request':list(hashlib.sha256(b'SAVANA_EXPERIMENT_PREPARE_V1\0'+bytes(compiled['request'])).digest()),
            'operation':dict(kind='prepare_planning_execution',task=list(task),root=root)}
        prepared=self._submit(directory,'prepare',command,wait=True)
        prior=json.loads(private_read(directory/'compile.receipt.json'))['result']
        approval=prepared['approval']
        if (prepared['kind']!='planning_execution_prepared' or prepared['task']!=list(task)
            or approval['task']!=list(task) or approval['root']!=root or approval['profile']!=prior['profile']
            or approval['recipe_schema']!=2 or len(approval['bindings'])!=1
            or approval['bindings'][0]['operation']!=1 or not approval['inputs_digest']):
            raise ValueError('kernel_recipe_binding')
        from savana.managed_admin import prepare_artifact
        native=prepare_artifact('recipe_approval',canonical(approval))
        approved={**compiled,'request':list(hashlib.sha256(b'SAVANA_EXPERIMENT_RECIPE_V1\0'+bytes(compiled['request'])).digest()),
            'operation':dict(kind='approve_planning_recipes',approval=approval,
                approval_signature=list(self.key.sign(native.signing_digest())))}
        result=self._submit(directory,'approve-recipe',approved)
        if result['kind']!='planning_recipes_approved' or result['approval']!=list(native.signing_digest()):
            raise ValueError('recipe_installation_not_confirmed')
        return dict(task_id=task.hex(),run_id=bytes(prepared['run']).hex(),root_digest=bytes(root).hex(),
            profile=bytes(prior['profile']).hex(),inputs_digest=bytes(approval['inputs_digest']).hex(),
            recipe_approval=bytes(result['approval']).hex())

    def handle(self, request):
        if type(request) is not dict: raise ValueError('operator_request')
        if request.get('kind')=='compile': return self.compile(request)
        if request.get('kind')=='prepare': return self.prepare(request)
        raise ValueError('unsupported_operator_request')


def main():
    if os.geteuid()!=0 or os.environ.get('LISTEN_PID')!=str(os.getpid()) or os.environ.get('LISTEN_FDS')!='1':
        raise ValueError('root_socket_activation_required')
    if os.environ.get('LISTEN_FDNAMES')!='savana-experiment-operator': raise ValueError('operator_listener')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key=Ed25519PrivateKey.from_private_bytes(private_read(
        '/run/credentials/savana-experiment-operator.service/managed-admin-v04.seed',32))
    deployment=json.loads(Path('/etc/savana/experiment-provisioning-v04.json').read_bytes())
    operator=FiniteOperator(deployment,key,STATE)
    uid=pwd.getpwnam('savana-experiment').pw_uid
    with socket.socket(fileno=os.dup(3)) as listener:
        if listener.family!=socket.AF_UNIX or listener.getsockname()!=SOCKET or not listener.getsockopt(socket.SOL_SOCKET,socket.SO_ACCEPTCONN):
            raise ValueError('operator_listener')
        while True:
            channel,_=listener.accept()
            with channel:
                channel.settimeout(125)
                try:
                    pid,peer,gid=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                    if pid<=0 or peer!=uid or gid!=uid: raise ValueError('experiment_peer_required')
                    result=operator.handle(receive(channel))
                    send(channel,dict(status='ready',result=result))
                except Exception:
                    try: send(channel,dict(status='not_confirmed',result=None))
                    except OSError: pass


if __name__=='__main__': main()
