#!/usr/bin/env python3
"""Fresh disposable Linux B installation. Never upgrade/delete an installation.

Requires a root-created /run/savana-file-backed-disposable marker and systemd.
Private material is generated on the target host, not uploaded from a laptop.
An incomplete attempt is deliberately not auto-erased; inspect it or discard
the disposable host. No task root, consent or model response is fabricated.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import grp
import shutil
import subprocess
import tempfile
import time
import http.client

SERVICES = ("kerneld", "agentd", "ingressd", "approvald", "execd")
ACCOUNTS = dict(zip(SERVICES, ("kernel", "agent", "ingress", "approval", "exec")))


def service_units(repo, *, protected_experiment=False):
    """Return the exact measured base units and required feature drop-ins."""
    units = {}
    for service in SERVICES:
        base = (repo / f"deploy/systemd/savana-{service}.service").read_text()
        base = base.replace("/credentials/shared/", f"/credentials/{service}/")
        base = base.replace("LoadCredentialEncrypted=connector-authority-v2.seed\n", "")
        if service in {"kerneld", "execd"}:
            base = base.replace("Type=simple\n", "Type=notify\nNotifyAccess=main\nTimeoutStartSec=120s\n")
        # Socket activation owns the socket lifetime. A failed daemon must not
        # recursively unlink sockets that systemd still considers listening.
        base = base.replace("RuntimeDirectoryMode=0711\n", "RuntimeDirectoryMode=0711\nRuntimeDirectoryPreserve=yes\n")
        if service == "approvald":
            # The root-only administrator socket must not live below a
            # service-writable directory. tmpfiles owns this parent; letting
            # RuntimeDirectory manage it would chown it back on restart.
            base = base.replace("RuntimeDirectory=savana/approvald\n", "")
        if service == "kerneld" and protected_experiment:
            # Include the new credential in the measured base unit, not an
            # unmeasured environment override or general-purpose key directory.
            base = base.replace("[Service]\n", "[Service]\nLoadCredentialEncrypted=fused-model-client-v04.pk8:/etc/savana/credentials/kerneld/fused-model-client-v04.pk8.cred\n")
        units[f"/usr/lib/systemd/system/savana-{service}.service"] = base
        units[f"/etc/systemd/system/savana-{service}.service.d/identity-broker.conf"] = (repo / "deploy/systemd/savana-identity-broker-client-v2.conf").read_text()
    for service, source in [("kerneld", "savana-kerneld-approval-v04.conf"),
                            ("approvald", "savana-approvald-kernel-v04.conf"),
                            ("execd", "savana-execd-split-final-release.conf")]:
        units[f"/etc/systemd/system/savana-{service}.service.d/{source}"] = (repo / "deploy/systemd" / source).read_text()
    if protected_experiment:
        units["/etc/systemd/system/savana-kerneld.service.d/managed-admin-v04.conf"] = (repo / "deploy/systemd/savana-kerneld-managed-admin-v04.conf").read_text()
    return units


def validate_credential_coverage(stage, units):
    """Fail before installation if any enabled service credential is missing."""
    for content in units.values():
        for line in content.splitlines():
            if not line.startswith("LoadCredentialEncrypted="):
                continue
            name, source = line.split("=", 1)[1].split(":", 1)
            path = Path(source)
            relative = path.relative_to("/etc/savana/credentials")
            if relative.name != name + ".cred" or not (stage / "private" / relative.parent / name).is_file():
                raise ValueError("missing integration credential: " + name)


def experiment_units(repo):
    """Optional non-kernel units, installed but never started/enabled here."""
    return {f"/usr/lib/systemd/system/{name}.{suffix}":
        (repo / f"deploy/systemd/{name}.{suffix}").read_text()
        for name in ('savana-protected-experiment','savana-experiment-operator','savana-experiment-auth')
        for suffix in ("service", "socket")}


def command(*args):
    subprocess.run(args, check=True, timeout=120)


def seal_experiment_runtime(repo):
    """Root control services must not execute an experiment-writable venv.

    Only the explicitly provisioned disposable runtime is sealed. Symlink
    targets are never recursively chowned; outside targets must already be
    protected system executables/libraries.
    """
    import stat
    venv=Path('/opt/savana-bench-venv')
    if repo!=Path('/opt/savana-protected') or not venv.is_dir() or venv.is_symlink():
        raise RuntimeError('closed protected experiment runtime required')
    for root in (repo,venv):
        if root.is_symlink():raise RuntimeError('runtime symlink')
        for path in [root,*root.rglob('*')]:
            m=path.lstat()
            if stat.S_ISLNK(m.st_mode):
                target=path.resolve(strict=True)
                if not target.is_relative_to(root):
                    if not str(target).startswith('/usr/') or target.stat().st_uid!=0 or target.stat().st_mode&0o022:
                        raise RuntimeError('untrusted runtime symlink target')
                os.chown(path,0,0,follow_symlinks=False)
            elif stat.S_ISDIR(m.st_mode) or stat.S_ISREG(m.st_mode):
                os.chown(path,0,0)
                path.chmod(0o755 if stat.S_ISDIR(m.st_mode) or m.st_mode&0o111 else 0o644)
            else:raise RuntimeError('unexpected runtime object')


def put(path, data, mode=0o444):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    # These are only the installer's closed public artifact destinations.
    # Explicitly set the mode: the root staging umask is deliberately 0077.
    path.parent.chmod(0o755)
    # Never follow a symlink or truncate a pre-existing deployment artifact.
    with path.open("xb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())
    path.chmod(mode)


def install_public_artifacts(stage, root):
    for subtree in ["etc/savana", "usr/libexec/savana"]:
        destination_root = root / subtree
        destination_root.mkdir(mode=0o755, parents=True, exist_ok=False)
        destination_root.chmod(0o755)
        for source in sorted((stage / subtree).rglob("*")):
            destination = root / source.relative_to(stage)
            if source.is_dir():
                destination.mkdir(mode=0o755, parents=True, exist_ok=True)
                destination.chmod(0o755)
            else:
                # Offline generators inherit the root staging umask (0077).
                # Public signed metadata must be exactly 0444 after install,
                # not 0400/0600 merely copied from its private staging mode.
                mode=0o755 if source.stat().st_mode&0o111 else 0o444
                put(destination, source.read_bytes(), mode)


def verify_owner_control():
    # A measured health exchange only: do not mint a task as an install probe.
    raw = subprocess.check_output(
        ["/usr/libexec/savana/savana-integration-admin", "owner-health"],
        timeout=40, text=True)
    if json.loads(raw) != {"state": "ready"}:
        raise RuntimeError("native owner control is not ready")


def verify_services(*, owner_control=False):
    # Type=simple can report active before startup validation fails. Require
    # stable PIDs/restart counters and a real signed administration round trip.
    previous = None
    for attempt in range(16):
        current = subprocess.check_output(["systemctl", "show", "--property=ActiveState,SubState,MainPID,NRestarts",
            *(f"savana-{service}.service" for service in SERVICES)], timeout=15, text=True)
        fields = [line for line in current.splitlines() if line]
        if fields.count("ActiveState=active") != 5 or fields.count("SubState=running") != 5 or "MainPID=0" in fields:
            raise RuntimeError("integration services did not remain running")
        if previous is not None and current != previous:
            raise RuntimeError("integration services restarted during verification")
        previous = current
        if attempt < 15:
            time.sleep(1)
    health = subprocess.check_output(["/usr/libexec/savana/savana-integration-admin", "health"], timeout=45, text=True)
    if health.strip() != "state=Ready":
        raise RuntimeError("signed approval administration health is not ready")
    connection = http.client.HTTPConnection("127.0.0.1", 8766, timeout=10)
    try:
        connection.request("GET", "/v2/enrollment/bootstrap", headers={"Host": "localhost:8766"})
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError("native enrollment page is unavailable")
        response.read(1024)
    finally:
        connection.close()
    if owner_control:
        verify_owner_control()
    # Admin health and HTTP must not hide a crash after the earlier samples.
    final = subprocess.check_output(["systemctl", "show", "--property=ActiveState,SubState,MainPID,NRestarts",
        *(f"savana-{service}.service" for service in SERVICES)], timeout=15, text=True)
    if final != previous:
        raise RuntimeError("integration services changed during health verification")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file-backed-integration", action="store_true", required=True)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--owner-control", action="store_true", help="install the measured native task-entry client (not a full intake)")
    parser.add_argument("--protected-experiment", action="store_true", help="enable separately pinned admin and Unix model transport; no task consent")
    parser.add_argument("--reuse-disposable-accounts", action="store_true", help="reuse validated isolated accounts after an explicitly authorized, archived replacement")
    args = parser.parse_args()
    if args.protected_experiment and not args.owner_control:
        parser.error("--protected-experiment requires --owner-control")
    if os.geteuid() != 0 or not Path("/run/systemd/system").is_dir():
        raise SystemExit("native root/systemd installation required")
    marker = Path("/run/savana-file-backed-disposable")
    if not marker.is_file() or marker.is_symlink() or marker.stat().st_uid != 0 or marker.stat().st_mode & 0o022:
        raise SystemExit("missing trusted disposable-host marker")
    for path in ["/etc/savana", "/usr/libexec/savana", "/var/lib/savana"]:
        if Path(path).exists() or Path(path).is_symlink():
            raise SystemExit("refusing existing Savana deployment")
    # The disposable host's cost/expiry guard is intentionally provisioned
    # before this installer. It is not a kernel deployment; never remove it.
    expiry_units = {"savana-acceptance-expiry.service", "savana-acceptance-expiry.timer"}
    existing_units = [path for directory in ["/etc/systemd/system", "/usr/lib/systemd/system"]
                      for path in Path(directory).glob("savana-*") if path.name not in expiry_units]
    if existing_units:
        raise SystemExit("refusing existing Savana units")
    repo = Path(__file__).resolve().parents[3]
    binaries = args.binaries.resolve(strict=True)
    if args.protected_experiment:
        seal_experiment_runtime(repo)
    for name in [*("savana-" + s for s in SERVICES), "savana-development-build-inputs", "savana-linux-integration-manifest", "savana-approvalctl", "savana-linux-identity-broker", "savana-systemd-agentd-network-policy-v2", "savana-worker-sandbox", "savana-parser-worker", "savana-connector-worker", *(["savana-ownerctl"] if args.owner_control else [])]:
        if not (binaries / name).is_file() or (binaries / name).is_symlink():
            raise SystemExit("missing built Linux executable: " + name)
    accounts = (*ACCOUNTS.values(), "jarvis", "identity", *(["experiment"] if args.protected_experiment else []))
    existing_names = {entry.pw_name for entry in pwd.getpwall()} | {entry.gr_name for entry in grp.getgrall()}
    if not args.reuse_disposable_accounts and any("savana-" + account in existing_names for account in accounts):
        raise SystemExit("refusing existing Savana accounts")
    if args.reuse_disposable_accounts:
        proof=Path('/run/savana-authorized-replacement.json')
        if (not proof.is_file() or proof.is_symlink() or proof.stat().st_uid!=0 or proof.stat().st_mode&0o077
                or json.loads(proof.read_bytes()).get('profile')!='file-backed-integration'):
            raise SystemExit('missing private disposable replacement receipt')
    used = {entry.pw_uid for entry in pwd.getpwall()} | {entry.gr_gid for entry in grp.getgrall()}
    free = [number for number in range(64001, 65000) if number not in used][:len(accounts)]
    if len(free) != len(accounts):
        raise SystemExit("no free isolated identity pairs")
    for account, number in zip(accounts, free):
        if args.reuse_disposable_accounts and 'savana-'+account in existing_names:
            group=grp.getgrnam('savana-'+account)
            minimum=1 if account=='experiment' else 64001
            if not minimum<=group.gr_gid<65000: raise SystemExit('invalid existing isolated group')
            if account!='identity':
                user=pwd.getpwnam('savana-'+account)
                if user.pw_uid!=group.gr_gid or user.pw_gid!=group.gr_gid or user.pw_shell!='/usr/sbin/nologin':
                    raise SystemExit('invalid existing isolated account')
            continue
        command("groupadd", "--gid", str(number), "savana-" + account)
        if account != "identity":
            command("useradd", "--uid", str(number), "--gid", str(number), "--no-create-home", "--shell", "/usr/sbin/nologin", "savana-" + account)
    ids = {s: pwd.getpwnam("savana-" + a).pw_uid for s,a in {**ACCOUNTS, "jarvis":"jarvis"}.items()}
    # Allocate explicit free pairs, then verify the actual installed identities.
    for service, account in {**ACCOUNTS, "jarvis":"jarvis"}.items():
        user = pwd.getpwnam("savana-" + account)
        if user.pw_uid != user.pw_gid:
            raise SystemExit("installer requires matched fresh UID/GID; allocate explicit free pairs before installation")
    for account in ACCOUNTS.values():
        command("usermod", "-a", "-G", "savana-identity", "savana-" + account)
    os.umask(0o077)
    # The manifest author checks every seed ancestor, so a world-writable
    # /var/tmp ancestor is invalid even with a private leaf directory.
    work = Path(tempfile.mkdtemp(prefix="savana-linux-integration-", dir="/root"))
    templates = work / "templates"
    templates.mkdir()
    command(str(binaries / "savana-development-build-inputs"), str(templates))
    spec = importlib.util.spec_from_file_location("savana_linux_assemble", Path(__file__).with_name("assemble.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    stage = work / "stage"
    module.assemble(templates, binaries, repo, stage, ids, owner_control=args.owner_control,
                    protected_experiment=args.protected_experiment)
    if args.protected_experiment:
        command(str(binaries / "savana-development-build-inputs"),
                "--protected-experiment-profile", str(stage))
    units = service_units(repo, protected_experiment=args.protected_experiment)
    validate_credential_coverage(stage, units)
    # Install only the explicit new configuration and binary subtrees. Private
    # staging material stays root-only on this disposable machine.
    install_public_artifacts(stage, Path("/"))
    Path("/etc/savana/trust").mkdir(mode=0o755, exist_ok=True)
    # Every source credential is delivered through systemd's encrypted credential
    # facility, using its host-key backend (B, not TPM). Bind encryption to ID.
    for service_dir in (stage / "private").iterdir():
        if not service_dir.is_dir():
            continue
        for source in service_dir.iterdir():
            destination = Path(f"/etc/savana/credentials/{service_dir.name}/{source.name}.cred")
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            command("systemd-creds", "encrypt", "--with-key=host", "--name=" + source.name, str(source), str(destination))
            destination.chmod(0o600)
    for service in SERVICES:
        account = pwd.getpwnam("savana-" + ACCOUNTS[service])
        state = Path("/var/lib/savana") / service
        state.mkdir(parents=True, mode=0o700)
        os.chown(state, account.pw_uid, account.pw_gid)
        state.chmod(0o700)
    Path("/var/lib/savana").chmod(0o755)
    sockets = ["kerneld-agent", "kerneld-ingress", "execd", "agentd-control", "agentd-jarvis-http", "agentd-agent-http",
               "ingressd-http", "approvald-agent", "approvald-ingress", "approvald-admin", "approvald-http", "approvald-kernel-v04", "identity-broker-v2"]
    if args.protected_experiment:
        sockets.append("kerneld-managed-admin-v04")
    for name in sockets:
        put(f"/usr/lib/systemd/system/savana-{name}.socket", (repo / f"deploy/systemd/savana-{name}.socket").read_bytes())
    put("/usr/lib/systemd/system/savana-identity-broker-v2.service", (repo / "deploy/systemd/savana-identity-broker-v2.service").read_bytes())
    for path, content in units.items():
        put(path, content.encode())
    if args.protected_experiment:
        for path, content in experiment_units(repo).items():
            put(path, content.encode())
        account = pwd.getpwnam("savana-experiment")
        for name in ("/var/lib/savana-benchmark", "/var/lib/savana-benchmark/runs"):
            Path(name).mkdir(mode=0o700)
            os.chown(name, account.pw_uid, account.pw_gid)
            Path(name).chmod(0o700)
        endpoint=json.loads((stage/'etc/savana/experiment-endpoints-v04.json').read_bytes())
        endpoint.pop('entries')
        endpoint.update(schema=3,operator_socket='/run/savana-experiment-operator/operator.sock',
            provisioning=json.loads((stage/'etc/savana/experiment-provisioning-v04.json').read_bytes()))
        config=Path('/var/lib/savana-benchmark/operator-bindings.json')
        put(config,json.dumps(endpoint,separators=(',',':')).encode(),0o600)
        os.chown(config,account.pw_uid,account.pw_gid)
        config.parent.chmod(0o700)
    put("/usr/libexec/savana/savana-integration-admin", Path(__file__).with_name("admin.py").read_bytes(), 0o755)
    if args.protected_experiment:
        put('/usr/libexec/savana/savana-experiment-admin',
            b'#!/bin/sh\nexport PYTHONPATH=/opt/savana-protected/python:/opt/savana-protected/experiments\nexec /opt/savana-bench-venv/bin/python -m savana_bench.protected_admin "$@"\n',0o755)
    # Explicit role-owned parents must exist before systemd creates sockets.
    lines = ["d /run/savana 0711 root root -", "d /run/savana-identity 0755 root root -"]
    for service, account in ACCOUNTS.items():
        owner = "root root" if service == "approvald" else f"savana-{account} savana-{account}"
        lines.append(f"d /run/savana/{service} 0711 {owner} -")
    for service, peer, group in [("kerneld","agentd","agent"), ("kerneld","ingressd","ingress"), ("execd","kerneld","kernel"),
        ("agentd","jarvis","jarvis"), ("approvald","agentd","agent"), ("approvald","ingressd","ingress"), ("approvald","kerneld","kernel")]:
        # All five readers stat the three manifest observation sockets. Permit
        # traversal, not listing or connecting: sockets retain exact 0660 and
        # their role-specific groups. Other private edges stay 0710.
        measured = (service, peer) in {("kerneld", "agentd"), ("execd", "kerneld"), ("agentd", "jarvis")}
        mode = "0711" if measured else "0710"
        lines.append(f"d /run/savana/{service}/{peer} {mode} savana-{ACCOUNTS[service]} savana-{group} -")
    lines.append("d /run/savana/approvald/admin 0700 root root -")
    if args.protected_experiment:
        lines.append("d /run/savana/kerneld/admin 0711 root root -")
        lines.append("d /run/savana-model 0711 root root -")
    # Approvald must stat its inherited root-only listener. A traverse-only
    # named ACL grants no listing or socket connection (socket remains 0600).
    lines.append("a+ /run/savana/approvald/admin - - - - u:savana-approval:--x")
    put("/usr/lib/tmpfiles.d/savana-file-backed-integration.conf", ("\n".join(lines)+"\n").encode())
    command("systemd-tmpfiles", "--create", "/usr/lib/tmpfiles.d/savana-file-backed-integration.conf")
    command("/usr/libexec/savana/savana-systemd-agentd-network-policy-v2", "install", "/etc/savana/agentd-bootstrap-v2.json")
    command("systemctl", "daemon-reload")
    command("systemctl", "start", *(f"savana-{name}.socket" for name in sockets))
    manifest = "/usr/libexec/savana/savana-linux-integration-manifest"
    command(manifest, "--file-backed-integration", str(stage / "private/manifest.seed"))
    command(manifest, "--check-startup")
    # Deliberately not the production recovery target: its TPM/V3 acceptance
    # gate is not satisfied by B's file-backed installation.
    command("systemctl", "start", "savana-identity-broker-v2.service", *(f"savana-{s}.service" for s in SERVICES))
    command("systemctl", "is-active", *(f"savana-{s}.service" for s in SERVICES))
    verify_services(owner_control=args.owner_control)
    put("/etc/savana/integration-status.json", json.dumps(dict(profile="file-backed-integration", production_security_accepted=False,
        five_services_started=True, owner_control_enabled=args.owner_control,
        protected_experiment_transport_configured=args.protected_experiment,
        user_authenticated=False, private_intake_configured=False)).encode())
    print("Five integration services started. No user authentication or task consent has been performed.")


if __name__ == "__main__":
    main()
