#!/usr/bin/env python3
"""Fresh offline container only: exact systemd ACLs, real non-root readers.

No existing credentials are accepted or touched. This is a filesystem/process
test, not evidence that a systemd service has started on the target AWS host.
"""
import os
from pathlib import Path
import struct
import subprocess
import sys


def acl(uid, permission, *, other=0):
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *row) for row in [
        (1, permission, 0xffffffff), (2, permission, uid), (4, 0, 0xffffffff),
        (16, permission, 0xffffffff), (32, other, 0xffffffff),
    ])


def main():
    if sys.argv[1:] != ["--disposable-container"] or os.geteuid() != 0:
        raise SystemExit("disposable root container required")
    if not Path("/.dockerenv").is_file() or not Path("/run/savana-credentials-test-only").is_file():
        raise SystemExit("explicit disposable marker required")
    root = Path("/run/credentials")
    root.mkdir(mode=0o755)  # Existing credentials are never reused.
    probe = "/build/debug/examples/linux_credential_probe"
    roles = ["kernel", "agent", "ingress", "approval", "exec"]
    count = 0

    def run(role, uid, expected, limit=32):
        nonlocal count
        subprocess.run([probe, role, str(limit), expected], user=uid, group=uid,
                       extra_groups=[], check=True, timeout=5)
        count += 1

    for index, role in enumerate(roles):
        uid = 64001 + index
        directory = root / f"savana-{role}d.service"
        directory.mkdir(mode=0o500)
        os.setxattr(directory, "system.posix_acl_access", acl(uid, 5))
        path = directory / "synthetic.key"
        path.write_bytes(b"7" * 32)
        path.chmod(0o400)
        os.setxattr(path, "system.posix_acl_access", acl(uid, 4))
        run(role, uid, "accept")
        run(role, uid + 100, "reject")
        run(role, 0, "reject")
        run(role, uid, "reject", 31)
        os.setxattr(path, "system.posix_acl_access", acl(uid, 4, other=4))
        run(role, uid, "reject")
        os.setxattr(path, "system.posix_acl_access", acl(uid, 6))
        run(role, uid, "reject")
        os.setxattr(path, "system.posix_acl_access", acl(uid, 4))
        alias = directory / "hardlink"
        os.link(path, alias)
        run(role, uid, "reject")
        alias.unlink()  # Only this fresh synthetic file in the disposable container.
        path.rename(directory / "real.key")
        path.symlink_to(directory / "real.key")
        run(role, uid, "reject")
        path.unlink()
        (directory / "real.key").rename(path)
        path.chmod(0o400)
        os.removexattr(path, "system.posix_acl_access")
        os.chown(path, uid, uid)
        # Ownership fallback is forbidden on writable filesystems.
        run(role, uid, "reject")
        path.write_bytes(b"7" * 8192)
        os.chown(path, 0, 0)
        os.setxattr(path, "system.posix_acl_access", acl(uid, 4))
        run(role, uid, "accept", 128 * 1024)
        print(f"{role}: exact ACL, isolation, size, permissions, links and TLS blob verified", flush=True)
    print(f"checks={count} native_systemd_acceptance=false")


if __name__ == "__main__":
    main()
