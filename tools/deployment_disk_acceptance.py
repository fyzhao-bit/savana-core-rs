#!/usr/bin/env python3
"""Run the root-owned journal file contract only inside disposable tmpfs Docker."""
import os
from pathlib import Path
import re
import subprocess

TESTS = (
    'linux_deployment_journal_v3::tests::disposable_root_disk_contract',
    'deployment_invocation::staging_v3::tests::staging_disposable_root_fixed_spool_contract',
)


def main():
    if (os.geteuid() != 0 or not Path('/.dockerenv').is_file()
            or not Path('/run/savana-deployment-disk-test-only').is_file()
            or Path('/dev/tpm0').exists() or Path('/dev/tpmrm0').exists()):
        raise SystemExit('requires explicitly marked, offline root test container without TPM')
    mounts = Path('/proc/mounts').read_text().splitlines()
    for parent in ['/var/lib/savana', '/var/lib/savana-deploy']:
        if not any(row.split()[1:3] == [parent, 'tmpfs'] for row in mounts):
            raise SystemExit('refusing a non-tmpfs test parent')
        if any(Path(parent).iterdir()):
            raise SystemExit('requires fresh empty test tmpfs')
    candidates = []
    for base in [Path('/build/debug/deps'), Path('/cache/debug/deps')]:
        if not base.is_dir():
            continue
        for path in base.iterdir():
            if re.fullmatch(r'savana_platform_identity-[0-9a-f]+', path.name) and path.is_file():
                result = subprocess.run([str(path), '--list'], check=True,
                                        text=True, capture_output=True, timeout=30)
                if all(f'{test}: test' in result.stdout.splitlines() for test in TESTS):
                    candidates.append(path)
    if len(candidates) != 1:
        raise SystemExit('requires one unambiguous freshly built test binary')
    for test in TESTS:
        result = subprocess.run([str(candidates[0]), test, '--exact', '--ignored'],
                                check=False, text=True, capture_output=True, timeout=60)
        print(result.stdout, end='')
        if result.returncode or '1 passed; 0 failed; 0 ignored;' not in result.stdout:
            raise SystemExit('required native disk/staging contract failed')
    print('Root-owned journal and staging tmpfs contracts: passed; systemd/TPM hardware acceptance: NOT RUN')


if __name__ == '__main__':
    main()
