#!/usr/bin/env python3
"""Synthetic authoring check, only inside an explicitly disposable container.

This does NOT start Savana, authenticate a person, or prove hardware security.
Never point this at an installed machine. Mount fresh /etc/savana,
/usr/libexec/savana, /usr/lib/systemd/system and /run as tmpfs.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys


def main():
    if sys.argv[1:] != ["--disposable-container"] or os.geteuid() != 0:
        raise SystemExit("disposable root container required")
    if not Path("/.dockerenv").is_file() or not Path("/run/savana-integration-manifest-test-only").is_file():
        raise SystemExit("explicit disposable marker required")
    os.umask(0o077)
    tool = Path("/build/debug/savana-linux-integration-manifest")
    services = ["kerneld", "agentd", "ingressd", "approvald", "execd"]
    accounts = ["kernel", "agent", "ingress", "approval", "exec"]
    configs = Path("/etc/savana")
    if list(configs.iterdir()):
        raise SystemExit("refusing existing Savana configuration")
    for index, account in enumerate(accounts):
        subprocess.run(["groupadd", "--gid", str(64001 + index), "savana-" + account], check=True)
        subprocess.run(["useradd", "--uid", str(64001 + index), "--gid", str(64001 + index),
                        "--no-create-home", "--shell", "/usr/sbin/nologin", "savana-" + account], check=True)
    subprocess.run(["groupadd", "--gid", "64006", "savana-jarvis"], check=True)
    listeners = []
    for path, uid, gid in [
        ("/run/savana/kerneld/agentd/kerneld.sock", 64001, 64002),
        ("/run/savana/kerneld/ingressd/kerneld.sock", 64001, 64003),
        ("/run/savana/execd/kerneld/execd.sock", 64005, 64001),
        ("/run/savana/agentd/jarvis/control.sock", 64002, 64006),
    ]:
        Path(path).parent.mkdir(parents=True, mode=0o755)
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(path)
        listener.listen()
        os.chown(path, uid, gid)
        os.chmod(path, 0o660)
        listeners.append(listener)
    digest = lambda s: hashlib.sha256(s.encode()).hexdigest()
    observations = []
    for index, service in enumerate(services):
        executable = Path(f"/usr/libexec/savana/savana-{service}")
        shutil.copyfile("/bin/true", executable)
        executable.chmod(0o755)
        unit = Path(f"/usr/lib/systemd/system/savana-{service}.service")
        shutil.copyfile(f"/workspace/deploy/systemd/savana-{service}.service", unit)
        unit.chmod(0o444)
        endpoint = {"kind": "loopback-tcp", "port": 8767 if index == 2 else 8766}
        if index in (0, 1, 4):
            endpoint = {"kind": "unix-socket", "path": {
                0: "/run/savana/kerneld/agentd/kerneld.sock",
                1: "/run/savana/agentd/jarvis/control.sock",
                4: "/run/savana/execd/kerneld/execd.sock",
            }[index]}
        observations.append(dict(service=service, service_identity=digest(service),
            process_uid=64001 + index, process_gid=64001 + index,
            executable_path=str(executable), config_path=f"/etc/savana/{service}-bootstrap-v2.json",
            sandbox_profile_path=str(unit), endpoint=endpoint,
            keystore_authority_identity=digest(service + "key"),
            rollback_authority_identity=digest(service + "anchor")))

    def write_json(path, value):
        # Only fixture files in this fresh disposable namespace.
        if path.exists():
            path.chmod(0o600)
        path.write_text(json.dumps(value))
        path.chmod(0o444)

    for service in services:
        write_json(configs / f"{service}-bootstrap-v2.json", {"services": observations})
    fields = "installation_id active_state_manifest_digest declassification_rule_set_digest protocol_abi_digest release_identity_digest model_set_identity_digest resource_profile_identity_digest approval_lock_identity_digest planner_lock_identity_digest executor_key_lock_identity_digest kernel_envelope_signing_key_id ledger_projection_identity effect_ledger_head_digest ledger_projection_signing_key_id ledger_projection_signing_public_key".split()
    template = {field: digest(field) for field in fields}
    template.update(active_state_manifest_sequence=1, deployment_generation=1, effect_fence_epoch=1,
                    edge_keys=[[digest(f"client-{i}"), digest(f"server-{i}")] for i in range(3)])
    write_json(configs / "integration-manifest-input.json", template)
    (configs / "trust").mkdir(mode=0o755)
    seed = configs / "synthetic.seed"
    seed.write_bytes(os.urandom(32))
    seed.chmod(0o600)
    command = [str(tool), "--file-backed-integration", str(seed)]

    def check(name, success):
        result = subprocess.run(command, capture_output=True, text=True)
        if (result.returncode == 0) != success:
            raise AssertionError(f"{name}: {result.stderr}")
        print(f"{name}: passed", flush=True)

    # All negative checks run before publication.
    seed.chmod(0o644)
    check("reject-public-seed", False)
    seed.chmod(0o600)
    socket_path = Path("/run/savana/kerneld/ingressd/kerneld.sock")
    os.chown(socket_path, 64001, 64002)
    check("reject-wrong-edge-group", False)
    os.chown(socket_path, 64001, 64003)
    malformed = json.loads(json.dumps(observations))
    malformed[0]["process_uid"] = 0
    write_json(configs / "approvald-bootstrap-v2.json", {"services": malformed})
    check("reject-divergent-bootstrap-observations", False)
    write_json(configs / "approvald-bootstrap-v2.json", {"services": observations})
    executable = Path(observations[0]["executable_path"])
    executable.chmod(0o777)
    check("reject-writable-executable", False)
    executable.chmod(0o755)
    template["edge_keys"][1] = template["edge_keys"][0]
    write_json(configs / "integration-manifest-input.json", template)
    check("runtime-verifier-rejects-reused-role-key", False)
    template["edge_keys"][1] = [digest("client-1"), digest("server-1")]
    write_json(configs / "integration-manifest-input.json", template)
    check("sign-and-runtime-verify-linux-manifest", True)
    before = (configs / "deployment-manifest-v2.cbor").read_bytes()
    check("reject-overwrite", False)
    assert (configs / "deployment-manifest-v2.cbor").read_bytes() == before
    assert (configs / "trust/deployment-manifest-root-v2.json").stat().st_mode & 0o777 == 0o444
    result = subprocess.run([str(tool), "--check-startup"], capture_output=True, text=True)
    assert result.returncode != 0, "manifest alone must not claim a ready deployment"
    print("reject-startup-without-signed-ledger-projection: passed")
    print("manifest_authoring=verified live_daemons=not_tested hardware_acceptance=false")
    for listener in listeners:
        listener.close()


if __name__ == "__main__":
    main()
