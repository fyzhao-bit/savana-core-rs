#!/usr/bin/env python3
"""Disposable synthetic TPM interoperability, never hardware acceptance.

Run unprivileged, offline, with fresh /tmp and writable build/cache mounts.
No host TPM, credentials, production state, enrollment or persistent handles.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    if not Path('/.dockerenv').is_file() or os.geteuid() == 0:
        raise SystemExit('requires an unprivileged disposable Docker context')
    if not Path('/run/savana-tpm-emulator-test-only').is_file():
        raise SystemExit('missing explicit emulator test marker')
    if Path('/dev/tpm0').exists() or Path('/dev/tpmrm0').exists():
        raise SystemExit('refusing access to a host TPM')
    with tempfile.TemporaryDirectory(prefix='savana-swtpm-') as root:
        root = Path(root)
        simulator = subprocess.Popen([
            'swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={root}',
            '--server', f'type=unixio,path={root}/tpm.sock',
            '--ctrl', f'type=unixio,path={root}/tpm.sock.ctrl',
            '--flags', 'not-need-init,startup-clear',
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            end = time.monotonic() + 10
            while not (root / 'tpm.sock').exists():
                if simulator.poll() is not None or time.monotonic() >= end:
                    raise RuntimeError('simulator startup failed')
                time.sleep(.02)
            env = dict(os.environ, TPM2TOOLS_TCTI=f'swtpm:path={root}/tpm.sock')
            def run(*args, input=None):
                result = subprocess.run(args, cwd=root, env=env, check=False, timeout=30,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, input=input)
                if result.returncode:
                    raise RuntimeError(f'{args[0]} synthetic fixture failed: {result.stderr.decode()}')
            # This authorization is public synthetic fixture data, not a secret.
            run('tpm2_createprimary', '-C', 'o', '-G', 'ecc256:ecdsa-sha256',
                '-g', 'sha256', '-a', 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign',
                '-p', 'hex:' + '06' * 32, '-c', 'key.ctx')
            run('tpm2_evictcontrol', '-C', 'o', '-c', 'key.ctx', '0x81010002')
            run('tpm2_readpublic', '-c', '0x81010002', '-o', 'public.bin', '-q', 'qualified.bin')
            run('tpm2_flushcontext', '-t')
            run('tpm2_nvdefine', '0x1500020', '-C', 'o', '-s', '32', '-a', '0x40044',
                '-p', 'hex:' + '08' * 32)
            run('tpm2_nvextend', '0x1500020', '-C', '0x1500020', '-P', 'hex:' + '08' * 32, '-i', '-',
                input=bytes([9]) * 32)
            # Trial policy and policy-only key: password alone must not authorize.
            run('tpm2_startauthsession', '-S', 'trial.ctx')
            run('tpm2_policypcr', '-S', 'trial.ctx', '-l', 'sha256:0,7')
            run('tpm2_policycommandcode', '-S', 'trial.ctx', 'TPM2_CC_Sign')
            run('tpm2_policypassword', '-S', 'trial.ctx', '-L', 'policy.bin')
            run('tpm2_flushcontext', 'trial.ctx')
            run('tpm2_pcrread', 'sha256:0,7', '-o', 'pcr.bin')
            run('tpm2_createprimary', '-C', 'o', '-G', 'ecc256:ecdsa-sha256',
                '-g', 'sha256', '-a', 'fixedtpm|fixedparent|sensitivedataorigin|adminwithpolicy|sign',
                '-L', 'policy.bin', '-p', 'hex:' + '06' * 32, '-c', 'policy-key.ctx')
            run('tpm2_evictcontrol', '-C', 'o', '-c', 'policy-key.ctx', '0x81010003')
            run('tpm2_readpublic', '-c', '0x81010003', '-o', 'policy-public.bin', '-q', 'policy-qualified.bin')
            run('tpm2_flushcontext', '-t')
            test_env = dict(os.environ, SAVANA_TPM_EMULATOR_FIXTURE=str(root))
            # --exact and a required one-pass result: ignored/missing tests may
            # never count as a successful simulator acceptance.
            result = subprocess.run([
                'cargo', 'test', '-p', 'savana-platform-identity', '--lib', '--locked', '--offline',
                'tpm_signature_v3::tests::swtpm_interoperability', '--', '--exact', '--ignored',
            ], env=test_env, check=False, timeout=180, text=True, stdout=subprocess.PIPE)
            print(result.stdout, end='')
            result.check_returncode()
            if '1 passed; 0 failed; 0 ignored;' not in result.stdout:
                raise RuntimeError('required exact emulator test did not run')
            print('TPM emulator interoperability: passed; hardware acceptance: NOT RUN')
        finally:
            simulator.terminate()
            try:
                simulator.wait(timeout=5)
            except subprocess.TimeoutExpired:
                simulator.kill()
                simulator.wait()


if __name__ == '__main__':
    main()
    # A separate fresh TPM is mandatory: this test owns occupied fixture slots.
    from tpm_first_install_acceptance import main as first_install
    first_install()
