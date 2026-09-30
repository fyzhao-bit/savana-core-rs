#!/usr/bin/env python3
"""Two fresh-container phases over a dedicated temporary volume, no real keys."""
import os
from pathlib import Path
import subprocess
import sys


def main():
    if os.geteuid() != 0 or not Path("/.dockerenv").exists():
        raise SystemExit("disposable root container only")
    if sys.argv[1:] not in [["setup"], ["check"]]:
        raise SystemExit("setup or check required")
    root = Path("/run/credentials")
    if sys.argv[1] == "setup":
        if list(root.iterdir()):
            raise SystemExit("refusing existing credential volume")
        root.chmod(0o755)
        for index, role in enumerate(["kernel", "agent", "ingress", "approval", "exec"]):
            uid = 64001 + index
            directory = root / f"savana-{role}d.service"
            directory.mkdir(mode=0o500)
            file = directory / "synthetic.key"
            file.write_bytes(b"7" * 32)
            file.chmod(0o400)
            os.chown(file, uid, 0)
            os.chown(directory, uid, 0)
        return
    if not os.statvfs(root).f_flag & os.ST_RDONLY:
        raise SystemExit("check requires read-only credential mount")
    for index, role in enumerate(["kernel", "agent", "ingress", "approval", "exec"]):
        for uid, expected in [(64001 + index, "accept"), (64101 + index, "reject"), (0, "reject")]:
            subprocess.run(["/build/debug/examples/linux_credential_probe", role, "32", expected],
                           user=uid, group=uid, extra_groups=[], check=True, timeout=5)
    print("readonly_root_group_fallback=verified checks=15 native_systemd_acceptance=false")


if __name__ == "__main__":
    main()
