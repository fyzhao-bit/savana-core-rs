"""Closed systemd launch for the optional Linux experiment deployment.

No command-line/env secret, root signing key, enrollment, direct kernel socket,
automatic restart or model fallback. The auth broker is a separate root-owned
local service. Default operation requires interactive passkey responses.
The explicit --software-benchmark mode requires a root-armed, single-use profile
and records that software identity/preconsent replaces human authentication.
"""
import json
import os
import secrets
from pathlib import Path
import socket
import stat
import struct
import sys
import uuid

from .protected_agentdojo import load_config, run

AUTH_SOCKET = '/run/savana-experiment-auth/owner.sock'
CONFIG = '/var/lib/savana-benchmark/operator-bindings.json'
CREDENTIALS = '/run/credentials/savana-protected-experiment.service'
OUTPUT = '/var/lib/savana-benchmark/runs'


def wait_for_browser_start(channel, identity_profile=None):
    """Pre-auth readiness over the existing broker, not direct kernel IPC."""
    from .protected_operator import receive, send
    launch_id=secrets.token_urlsafe(32)
    previous=channel.gettimeout()
    try:
        # This is only the idle readiness gate. WebAuthn/approval retain their
        # original deadlines after the user explicitly starts the experiment.
        channel.settimeout(905)
        extra={}
        if identity_profile is not None:
            import hashlib
            from .agentdojo_provider import canonical
            extra['benchmark_profile_sha256']=hashlib.sha256(canonical(identity_profile)).hexdigest()
        send(channel,dict(protocol_version=1,type='experiment.ready',launch_id=launch_id,**extra))
        value=receive(channel)
        if (type(value) is not dict or set(value)!={'protocol_version','type','launch_id','start'}|set(extra)
            or type(value['protocol_version']) is not int or value['protocol_version']!=1
            or value['type']!='experiment.start' or value['launch_id']!=launch_id
            or value['start'] is not True or any(value[k]!=v for k,v in extra.items())):
            raise ValueError('browser_start_not_confirmed')
    finally:channel.settimeout(previous)


def activation_fd(environment, pid):
    if (environment.get('LISTEN_PID') != str(pid)
            or environment.get('LISTEN_FDS') != '1'
            or environment.get('LISTEN_FDNAMES') != 'savana-fused-model-v04'):
        raise ValueError('exact_systemd_activation_required')
    return 3


def _root_path(path, *, socket_leaf=False):
    current = Path(path)
    for item in (current, *current.parents):
        meta = item.lstat()
        leaf = item == current
        valid_type = stat.S_ISSOCK(meta.st_mode) if leaf and socket_leaf else stat.S_ISDIR(meta.st_mode)
        forbidden = 0o007 if leaf and socket_leaf else 0o022
        if not valid_type or meta.st_uid != 0 or meta.st_mode & forbidden:
            raise ValueError('root_owned_broker_path_required')


def open_auth_broker():
    if sys.platform != 'linux':
        raise ValueError('native_linux_required')
    _root_path(AUTH_SOCKET, socket_leaf=True)
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        channel.settimeout(5)
        channel.connect(AUTH_SOCKET)
        pid, uid, gid = struct.unpack('3i', channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid <= 0 or uid != 0 or gid != 0:
            raise ValueError('root_owned_broker_peer_required')
        return channel
    except BaseException:
        channel.close()
        raise


def _credential_acl_grants_only(fd, uid):
    """Exact systemd >=254 delivery, matching the native Linux credential check:
    owner r, this UID r, no group/other access. Any other ACL is rejected."""
    try:
        raw = os.getxattr(fd, 'system.posix_acl_access')
    except OSError:
        return False
    undefined = 0xFFFFFFFF
    expected = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in (
        (0x01, 4, undefined), (0x02, 4, uid), (0x04, 0, undefined), (0x10, 4, undefined), (0x20, 0, undefined)))
    return raw == expected


def open_model_credential():
    if os.environ.get('CREDENTIALS_DIRECTORY') != CREDENTIALS:
        raise ValueError('systemd_credentials_required')
    fd = os.open(CREDENTIALS+'/deepseek-api-key', os.O_RDONLY | os.O_NOFOLLOW)
    try:
        meta = os.fstat(fd)
        # Older systemd delivers an owner-only file; newer systemd delivers
        # root:root 0440 plus an ACL naming only this service UID.
        owner_only = meta.st_uid in (0, os.geteuid()) and not meta.st_mode & 0o077
        exact_acl = (meta.st_uid == 0 and meta.st_gid == 0 and meta.st_nlink == 1
            and stat.S_IMODE(meta.st_mode) == 0o440 and _credential_acl_grants_only(fd, os.geteuid()))
        if (not stat.S_ISREG(meta.st_mode) or not (owner_only or exact_acl)
                or not 1 <= meta.st_size <= 256):
            raise ValueError('private_model_credential_required')
        return fd
    except BaseException:
        os.close(fd)
        raise


def main(argv=()):
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--software-benchmark',action='store_true')
    # Untrusted-planner experiment: honest | poisoned | compromised[:names].
    parser.add_argument('--planner-experiment')
    args=parser.parse_args(argv)
    identity_profile=None
    if args.planner_experiment is not None:
        from .planner_experiment import experiment_cases
        experiment_cases(args.planner_experiment)
        if not args.software_benchmark: raise ValueError('planner_experiment_requires_software_benchmark')
    if args.software_benchmark:
        from .benchmark_identity import load_profile
        identity_profile=load_profile()
    fd = activation_fd(os.environ, os.getpid())
    if os.geteuid() == 0:
        raise ValueError('unprivileged_experiment_identity_required')
    config = load_config(CONFIG)
    if identity_profile is not None and (config['schema']!=3
            or identity_profile['installation']!=config['provisioning']['installation']):
        raise ValueError('benchmark_deployment_binding')
    # Configuration cannot redirect systemd's narrowly loaded TLS credentials.
    expected = {'provider':'provider', 'release_provider':'final-release', 'model_worker':'model'}
    for role, prefix in expected.items():
        for field, suffix in (('certificate','-server.pem'), ('private_key','-server.pk8.pem'),
                               ('client_ca','-client-ca.pem')):
            if config[role][field] != CREDENTIALS+'/'+prefix+suffix:
                raise ValueError('deployment_credential_binding')
    from savana.fused_worker import inherited_listener
    checked = inherited_listener(fd, config['model_worker']['socket'])
    checked.close()
    # UUID is only a fresh output-directory name, never a task/root/run identity.
    root = Path(OUTPUT)
    meta = root.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.geteuid() or meta.st_mode & 0o077:
        raise ValueError('private_output_directory_required')
    output = root / uuid.uuid4().hex
    with open_auth_broker() as broker:
        print('Using explicitly armed software-identity benchmark; no human authentication claims.'
            if identity_profile else 'Waiting for explicit browser start; no authentication challenge or model call yet.',flush=True)
        wait_for_browser_start(broker,identity_profile)
        key_fd = open_model_credential()
        try:
            if args.planner_experiment is not None:
                from .planner_experiment import run as run_planner
                summary = run_planner(output=output, config=config, auth_fd=broker.fileno(),
                    model_key_fd=key_fd, model_listener_fd=fd, identity_profile=identity_profile,
                    experiment=args.planner_experiment)
            else:
                summary = run(output=output, config=config, auth_fd=broker.fileno(),
                    model_key_fd=key_fd, model_listener_fd=fd, identity_profile=identity_profile)
        finally:
            os.close(key_fd)
    print(json.dumps({k:summary[k] for k in ('run_status','protected_episodes_scored','episodes_attempted',
                                             'total_model_calls','blockers') if k in summary}))
    return 0 if summary['run_status']=='complete' else 2


if __name__=='__main__':
    try:
        raise SystemExit(main(None))
    except (OSError, ValueError):
        # No exception text containing configuration or credential bytes.
        print('Protected experiment launch was not confirmed; inspect private deployment prerequisites.', file=sys.stderr)
        raise SystemExit(2)
