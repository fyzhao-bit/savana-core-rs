#!/usr/bin/env python3
"""Explicit, recoverable replacement of ONE authorized file-backed test host.

Never use for production, TPM state migration or budget-reset/retry experiments.
Stops the deployment and archives old credentials/state/enrollments together.
The expiry guard is never stopped/moved. A partial replacement fails closed.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

PRESERVE={'savana-acceptance-expiry.service','savana-acceptance-expiry.timer'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--authorized-disposable-reset',action='store_true',required=True)
    args=p.parse_args()
    if os.geteuid()!=0: raise SystemExit('root required')
    marker=Path('/run/savana-file-backed-disposable')
    if not marker.is_file() or marker.is_symlink() or marker.stat().st_uid!=0 or marker.stat().st_mode&0o022:
        raise SystemExit('trusted disposable marker required')
    status=json.loads(Path('/etc/savana/integration-status.json').read_bytes())
    if status.get('profile')!='file-backed-integration' or status.get('production_security_accepted') is not False:
        raise SystemExit('only B test deployment may be replaced')
    subprocess.run(['systemctl','is-active','--quiet','savana-acceptance-expiry.timer'],check=True)
    roots=[Path(x) for x in ('/etc/savana','/usr/libexec/savana','/var/lib/savana')]
    for path in roots:
        m=path.lstat()
        if not stat.S_ISDIR(m.st_mode) or m.st_uid!=0: raise SystemExit('unexpected deployment root')
    units=[path for directory in ('/etc/systemd/system','/usr/lib/systemd/system')
        for path in Path(directory).glob('savana-*') if path.name not in PRESERVE]
    names=sorted({path.name for path in units if path.suffix in ('.socket','.service')})
    # Stop activation sockets first, then services, before archiving any state.
    for suffix in ('.socket','.service'):
        selected=[name for name in names if name.endswith(suffix)]
        if selected: subprocess.run(['systemctl','stop',*selected],check=True,timeout=120)
    active=subprocess.run(['systemctl','is-active',*names],stdout=subprocess.PIPE,text=True)
    if any(line in ('active','activating','deactivating') for line in active.stdout.splitlines()):
        raise SystemExit('deployment still active')
    backup=Path(tempfile.mkdtemp(prefix='savana-replaced-',dir='/root'))
    # /run is a separate tmpfs; sockets cannot be copied as regular files.
    # Keep their recoverable archive on that filesystem (persistent state stays /root).
    runtime_backup=Path(tempfile.mkdtemp(prefix='savana-runtime-replaced-',dir='/run'))
    paths=roots+units
    for exact in ('/run/savana','/run/savana-identity','/run/savana-model','/run/savana-experiment-auth',
                  '/run/savana-experiment-operator','/var/lib/savana-benchmark',
                  '/var/lib/savana-experiment-auth','/var/lib/savana-experiment-operator',
                  '/usr/lib/tmpfiles.d/savana-file-backed-integration.conf'):
        path=Path(exact)
        if path.exists() or path.is_symlink(): paths.append(path)
    for path in paths:
        destination=(runtime_backup if path.is_relative_to('/run') else backup)/str(path).lstrip('/')
        destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        path.rename(destination)
    receipt=dict(profile='file-backed-integration',archive=str(backup),runtime_archive=str(runtime_backup),
        old_state_reusable_for_new_experiments=False,expiry_preserved=True)
    target=Path('/run/savana-authorized-replacement.json')
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as out:json.dump(receipt,out);out.flush();os.fsync(out.fileno())
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','is-active','--quiet','savana-acceptance-expiry.timer'],check=True)
    print(json.dumps(receipt))


if __name__=='__main__':main()
