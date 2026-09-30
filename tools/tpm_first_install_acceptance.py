#!/usr/bin/env python3
"""Fresh synthetic TPM first-install path. Never provisions the host hardware."""
import os
from pathlib import Path
import subprocess
import tempfile
import time


def main():
    if (not Path('/.dockerenv').is_file() or os.geteuid() == 0
            or not Path('/run/savana-tpm-emulator-test-only').is_file()
            or Path('/dev/tpm0').exists() or Path('/dev/tpmrm0').exists()):
        raise SystemExit('requires explicitly marked, unprivileged disposable emulator container')
    with tempfile.TemporaryDirectory(prefix='savana-first-install-') as directory:
        root = Path(directory)
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
            # Read PCRs only. The Rust production backend must create every object.
            subprocess.run(['tpm2_pcrread', 'sha256:0,7', '-o', str(root / 'pcr.bin')],
                           env=dict(os.environ, TPM2TOOLS_TCTI=f'swtpm:path={root}/tpm.sock'),
                           check=True, timeout=30, stdout=subprocess.DEVNULL)
            result = subprocess.run([
                'cargo', 'test', '-p', 'savana-platform-identity', '--lib', '--locked', '--offline',
                'tpm_first_install::tests::swtpm_first_install', '--', '--exact', '--ignored',
            ], env=dict(os.environ, SAVANA_TPM_FIRST_INSTALL_FIXTURE=str(root)),
                check=False, timeout=180, text=True, stdout=subprocess.PIPE)
            print(result.stdout, end='')
            result.check_returncode()
            if '1 passed; 0 failed; 0 ignored;' not in result.stdout:
                raise RuntimeError('required exact first-install test did not run')
            print('First-install emulator: passed; host provisioning/hardware acceptance: NOT RUN')
        finally:
            simulator.terminate()
            try:
                simulator.wait(timeout=5)
            except subprocess.TimeoutExpired:
                simulator.kill()
                simulator.wait()


if __name__ == '__main__':
    main()
