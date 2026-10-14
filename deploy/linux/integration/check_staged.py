#!/usr/bin/env python3
"""Verify assembled REAL binaries/artifacts in a new disposable container.

This verifies signed startup artifacts, not running services or systemd.
Mount the freshly assembled private stage at /stage, read-only. Never upload it.
"""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys


def main():
    if sys.argv[1:] != ["--disposable-container"] or os.geteuid() != 0:
        raise SystemExit("explicit root disposable invocation required")
    if not Path("/.dockerenv").is_file() or not Path("/run/savana-staged-test-only").is_file():
        raise SystemExit("disposable marker required")
    for name in ["/etc/savana", "/usr/libexec/savana", "/run/savana"]:
        if Path(name).exists() or Path(name).is_symlink():
            raise SystemExit("refusing existing deployment")
    os.umask(0o077)
    repo = Path(__file__).resolve().parents[3]
    spec = importlib.util.spec_from_file_location("installer", Path(__file__).with_name("install.py"))
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    stage = Path("/stage")
    installer.install_public_artifacts(stage, Path("/"))
    Path("/etc/savana/trust").mkdir(mode=0o755, exist_ok=True)
    for path, content in installer.service_units(repo).items():
        installer.put(path, content.encode())
    for index, account in enumerate(["kernel", "agent", "ingress", "approval", "exec", "jarvis"]):
        uid = str(64001 + index)
        subprocess.run(["groupadd", "--gid", uid, "savana-" + account], check=True)
        subprocess.run(["useradd", "--uid", uid, "--gid", uid, "--no-create-home", "savana-" + account], check=True)
    listeners = []
    Path("/run/savana").mkdir(mode=0o711)
    for service, uid in zip(installer.SERVICES, range(64001, 64006)):
        directory = Path("/run/savana") / service
        directory.mkdir(mode=0o711)
        directory.chmod(0o711)
        os.chown(directory, uid, uid)
    for path, uid, gid in [
        ("/run/savana/kerneld/agentd/kerneld.sock", 64001, 64002),
        ("/run/savana/kerneld/ingressd/kerneld.sock", 64001, 64003),
        ("/run/savana/execd/kerneld/execd.sock", 64005, 64001),
        ("/run/savana/agentd/jarvis/control.sock", 64002, 64006),
    ]:
        Path(path).parent.mkdir(parents=True, mode=0o755)
        os.chown(Path(path).parent, uid, gid)
        os.chmod(Path(path).parent, 0o710 if "/ingressd/" in path else 0o711)
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(path)
        listener.listen()
        os.chown(path, uid, gid)
        os.chmod(path, 0o660)
        listeners.append(listener)
    seed = Path("/etc/savana/fresh-staging.seed")
    installer.put(seed, (stage / "private/manifest.seed").read_bytes(), 0o600)
    tool = "/usr/libexec/savana/savana-linux-integration-manifest"
    subprocess.run([tool, "--file-backed-integration", str(seed)], check=True)
    subprocess.run([tool, "--check-startup"], check=True)
    # Use the actual filesystem verifier under all five isolated service UIDs.
    # Public metadata traversal must not grant write/connect permission.
    Path("/run/savana").chmod(0o711)
    for uid in range(64001, 64006):
        subprocess.run(["/build/debug/examples/linux_startup_probe"], user=uid, group=uid,
                       extra_groups=[], check=True)
        for path, allowed in [
            ("/run/savana/kerneld/agentd/kerneld.sock", {64001, 64002}),
            ("/run/savana/execd/kerneld/execd.sock", {64001, 64005}),
            ("/run/savana/agentd/jarvis/control.sock", {64002, 64006}),
        ]:
            if uid in allowed:
                continue
            code = "import socket,sys\ns=socket.socket(socket.AF_UNIX)\ntry:\n s.connect(sys.argv[1])\nexcept PermissionError:\n sys.exit(0)\nsys.exit(1)\n"
            subprocess.run([sys.executable, "-c", code, path], user=uid, group=uid,
                           extra_groups=[], check=True)
    print("five_nonroot_startup_readers=verified ten_cross_role_connect_denials=verified")
    print("assembled_signed_artifacts=verified running_services=not_tested native_systemd_acceptance=false")
    for listener in listeners:
        listener.close()


if __name__ == "__main__":
    main()
