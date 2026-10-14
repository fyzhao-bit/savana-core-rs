#!/usr/bin/env python3
"""Root-only disposable Docker integration, not systemd/hardware acceptance.

Creates only fixed synthetic paths inside a read-only disposable container with
explicit tmpfs mounts. Do not run on the host or upload production state.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

BIN = Path("/usr/libexec/savana")
POLICY = Path("/etc/savana/identity-broker-v2.json")
RUNTIME = Path("/run/savana-identity")
SOCKET = RUNTIME / "measurement-v2.sock"
PROBES = Path("/run/savana-broker-acceptance")
UID_A, UID_B, EDGE_GID = 21001, 21002, 22000


def wait_for(predicate, seconds=10):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.02)
    raise RuntimeError("bounded_wait_failed")


def child_identity(uid):
    def apply():
        os.setgroups([EDGE_GID])
        os.setgid(uid)
        os.setuid(uid)
    return apply


def start_broker(policy):
    POLICY.write_text(json.dumps(policy))
    POLICY.chmod(0o600)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(SOCKET))
    SOCKET.chmod(0o660)
    os.chown(SOCKET, 0, EDGE_GID)
    listener.listen(8)
    pid = os.fork()
    if pid == 0:
        fd = listener.fileno()
        if fd != 3:
            os.dup2(fd, 3)
        os.set_inheritable(3, True)
        os.closerange(4, 1024)
        os.execve("/usr/bin/setpriv", ["setpriv", "--bounding-set=-all,+sys_ptrace",
                  "--inh-caps=-all", "--ambient-caps=-all", str(BIN / "savana-linux-identity-broker")],
                  {"PATH": "/usr/bin:/bin", "LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "1",
                   "LISTEN_FDNAMES": "identity-measurement-v2"})
    listener.close()
    return pid


def stop_broker(pid):
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    SOCKET.unlink(missing_ok=True)


def probe(name, expected, peer_uid=UID_B):
    path = PROBES / (name + ".sock")
    binary = str(BIN / "linux-peer-probe")
    server = subprocess.Popen([binary, "server", str(path)], preexec_fn=child_identity(UID_A),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    client = None
    try:
        wait_for(lambda: path.exists())
        client = subprocess.Popen([binary, "client", str(path)], preexec_fn=child_identity(peer_uid),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        client_out, client_error = client.communicate(timeout=15)
        if client.returncode != 0:
            raise RuntimeError("synthetic_client_failed:" + name + ":" + client_error[:1024])
        server_out, _ = server.communicate(timeout=15)
        actual = server.returncode == 0 and client.returncode == 0 and "measurement_accepted=true" in client_out
        if actual != expected or (not expected and server.returncode != 2):
            raise RuntimeError("unexpected_measurement_outcome:" + name)
        return {"case": name, "expected_accept": expected, "observed_accept": actual, "passed": True}
    finally:
        for process in (client, server):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
        path.unlink(missing_ok=True)


def main():
    if sys.argv[1:] != ["--disposable-container"] or os.geteuid() != 0 or not Path("/.dockerenv").is_file():
        raise SystemExit("requires explicit disposable Docker root context")
    if not Path("/run/savana-broker-test-only").is_file():
        raise SystemExit("missing disposable marker")
    for path in (POLICY, SOCKET, PROBES):
        if path.exists() or path.is_symlink():
            raise SystemExit("refusing existing test target")
    BIN.mkdir(parents=True, exist_ok=True)
    RUNTIME.mkdir(mode=0o755)
    PROBES.mkdir(mode=0o2770)
    os.chown(PROBES, 0, EDGE_GID)
    PROBES.chmod(0o2770)
    POLICY.parent.mkdir(parents=True, exist_ok=True)
    for source, destination in (("/build/debug/savana-linux-identity-broker", "savana-linux-identity-broker"),
                                ("/build/debug/examples/linux_peer_probe", "linux-peer-probe")):
        if (BIN / destination).exists() or (BIN / destination).is_symlink():
            raise SystemExit("refusing existing executable target")
        shutil.copyfile(source, BIN / destination)
        (BIN / destination).chmod(0o755)
    digest = list(hashlib.sha256((BIN / "linux-peer-probe").read_bytes()).digest())
    identity = lambda uid, value: {"uid": uid, "gid": uid, "executable_sha256": value}
    rows = [probe("broker_absent", False)]
    variants = (
        ("valid_cross_uid", UID_A, digest, digest, True),
        ("wrong_caller_hash", UID_A, [9] * 32, digest, False),
        ("wrong_peer_hash", UID_A, digest, [9] * 32, False),
        ("wrong_caller_uid", UID_A + 10, digest, digest, False),
    )
    for name, uid, caller_digest, peer_digest, expected in variants:
        policy = {"version": 2, "edges": [{"caller": identity(uid, caller_digest),
                                           "peer": identity(UID_B, peer_digest)}]}
        pid = start_broker(policy)
        try:
            rows.append(probe(name, expected))
        finally:
            stop_broker(pid)
    admin_policy = {"version": 2, "edges": [{"caller": identity(UID_A, digest),
                                             "peer": identity(0, digest)}]}
    pid = start_broker(admin_policy)
    try:
        rows.append(probe("explicit_root_admin_peer", True, peer_uid=0))
    finally:
        stop_broker(pid)
    rows.append(probe("broker_removed_no_fallback", False))
    print(json.dumps({"scope": "disposable_linux_container_cross_uid", "systemd_acceptance": False,
                      "hardware_acceptance": False, "cases": rows}, indent=2))


if __name__ == "__main__":
    main()
