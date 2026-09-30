"""Closed root administration for the disposable protected experiment.

One command to inspect/start; secrets only via a terminal or inherited private
FD. No signature bypass, fake passkey, kernel-state edits or automatic retries.
"""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

SERVICE='savana-protected-experiment.service'
KEY='/etc/savana/credentials/experiment/deepseek-api-key.cred'


def call(args,timeout=45):
    return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)


def task_correlation_trust(directory=Path('/etc/savana')):
    """Public-key wiring preflight, not a signature bypass or task issuance."""
    try:
        agent=json.loads((directory/'agentd-bootstrap-v2.json').read_bytes())
        approval=json.loads((directory/'approvald-bootstrap-v2.json').read_bytes())
        public=(directory/'agentd/keys/kerneld-task-authority-v2.pub').read_bytes()
        correlation=(directory/'approvald/keys/kerneld-correlation-v2.pub').read_bytes()
        expected=hashlib.sha256(b'savana.ed25519-key-id.v2\0'+public).hexdigest()
        return (len(public)==32 and public!=bytes(32) and public==correlation
            and agent['kernel_task_authority_key_id']==expected
            and approval['kernel_correlation_key_id']==expected)
    except (OSError,ValueError,KeyError,TypeError):
        return False


def authority_envelope_trust(directory=Path('/etc/savana')):
    """Check the measured approval pin without opening private credentials."""
    try:
        approval=json.loads((directory/'approvald-bootstrap-v2.json').read_bytes())
        public=bytes.fromhex(approval['kernel_authority_envelope_public_key'])
        execution=(directory/'approvald/keys/kerneld-envelope-v2.pub').read_bytes()
        correlation=(directory/'approvald/keys/kerneld-correlation-v2.pub').read_bytes()
        expected=hashlib.sha256(b'savana.ed25519-key-id.v2\0'+public).hexdigest()
        return (all(len(key)==32 and key!=bytes(32) for key in (public,execution,correlation))
            and len({public,execution,correlation})==3
            and approval['kernel_authority_envelope_key_id']==expected)
    except (OSError,ValueError,KeyError,TypeError):
        return False


def status():
    checks={}
    for name in ('kerneld','agentd','ingressd','approvald','execd'):
        value=subprocess.run(['systemctl','is-active','savana-'+name+'.service'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        checks[name]=value.returncode==0
    try:
        checks['owner_control']=json.loads(call(['/usr/libexec/savana/savana-integration-admin','owner-health']).stdout)=={'state':'ready'}
    except Exception:checks['owner_control']=False
    checks['task_correlation_trust']=task_correlation_trust()
    checks['authority_envelope_trust']=authority_envelope_trust()
    checks['model_key']=Path(KEY).is_file()
    checks['operator_config']=Path('/var/lib/savana-benchmark/operator-bindings.json').is_file()
    for name in ('auth','operator'):
        checks[name+'_socket']=subprocess.run(['systemctl','is-active','--quiet','savana-experiment-'+name+'.socket']).returncode==0
        checks[name+'_service']=subprocess.run(['systemctl','is-active','--quiet','savana-experiment-'+name+'.service']).returncode==0
    checks['auth_http']=False
    try:
        import http.client
        from .protected_operator import private_read
        token=private_read('/var/lib/savana-experiment-auth/browser.token',43).decode('ascii')
        connection=http.client.HTTPConnection('127.0.0.1',8786,timeout=3)
        try:
            connection.request('GET','/pending',headers={'Host':'localhost:8786','Origin':'http://localhost:8766','Authorization':'Bearer '+token})
            response=connection.getresponse();response.read(262144)
            checks['auth_http']=response.status==200
        finally:connection.close()
        del token
    except Exception:pass
    checks['expiry_guard']=subprocess.run(['systemctl','is-active','--quiet','savana-acceptance-expiry.timer']).returncode==0
    return dict(schema=1,checks=checks,ready_to_request_real_authentication=all(checks.values()),
        passkey_authentication_confirmed=False,full_agentdojo_benchmark=False,production_acceptance=False)


def install_model_key(data, *, transient=False):
    if Path(KEY).exists() or Path(KEY).is_symlink():raise ValueError('existing_model_credential_requires_explicit_rotation')
    if type(data) is not bytes or not 1<=len(data)<=256 or any(x<33 or x>126 for x in data):raise ValueError('invalid_model_key')
    command=['systemd-creds','encrypt','--with-key=host','--name=deepseek-api-key','-',KEY]
    if transient:
        command=['systemd-run','--quiet','--wait','--pipe','--collect',
            '--unit=savana-experiment-key-install.service','--service-type=exec',
            '--property=User=root','--property=UMask=0077','--property=NoNewPrivileges=yes',
            '--property=PrivateTmp=yes','--property=RuntimeMaxSec=30','--property=LimitCORE=0',
            '--',*command]
    # The secret is stdin, never command arguments, environment or SSM scripts.
    subprocess.run(command,input=data,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=35)


def configure_key(fd):
    if fd is None:
        data=getpass.getpass('DeepSeek API key (not echoed): ').encode('ascii')
    else:
        meta=os.fstat(fd)
        if fd<3 or not (stat.S_ISREG(meta.st_mode) or stat.S_ISFIFO(meta.st_mode)):
            raise ValueError('private_key_fd_required')
        if stat.S_ISREG(meta.st_mode) and (meta.st_uid!=0 or meta.st_mode&0o077):
            raise ValueError('private_root_key_file_required')
        data=os.read(fd,257).strip()
    install_model_key(data)
    del data
    Path(KEY).chmod(0o600)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('status','prepare-auth','configure-model','enroll','start'))
    p.add_argument('--key-fd',type=int)
    args=p.parse_args()
    if os.geteuid()!=0:raise SystemExit('root operator required')
    if args.action=='configure-model':
        configure_key(args.key_fd);print('Encrypted model credential installed; no model request sent.');return
    if args.key_fd is not None:raise SystemExit('key FD only accepted by configure-model')
    if args.action=='prepare-auth':
        call(['systemctl','start','savana-experiment-auth.socket','savana-experiment-operator.socket'])
        call(['systemctl','start','savana-experiment-auth.service','savana-experiment-operator.service'])
        print(json.dumps(status()));return
    if args.action=='enroll':
        # Only the invoking private terminal receives the one-use enrollment.
        subprocess.run(['/usr/libexec/savana/savana-integration-admin','enroll'],check=True,timeout=45);return
    state=status()
    if args.action=='status':print(json.dumps(state));return
    if not state['ready_to_request_real_authentication']:
        print(json.dumps(state));raise SystemExit(2)
    previous=Path('/var/lib/savana-benchmark/runs')
    if any(previous.iterdir()):raise SystemExit('Existing evidence retained. Review prior outcome before a separately identified run; no automatic retry.')
    call(['systemctl','start','savana-protected-experiment.socket',SERVICE])
    print('Experiment armed. Click Start experiment at http://localhost:8766/experiment-auth before any authentication challenge is issued. No score is confirmed yet.')


if __name__=='__main__':
    try:main()
    except (OSError,ValueError,subprocess.SubprocessError):
        raise SystemExit('Administration not confirmed. Preserve original state and inspect prerequisites.')
