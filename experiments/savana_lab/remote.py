"""Hosts on other machines: a brand-new machine per batch, over SSH.

    run = sl.run("u9c", sl.U9, host=sl.AwsHosts(region="us-east-1", security_group="sg-0123"))
    run = sl.run("u9c", sl.U9, host=sl.SshHosts(create="./new-vm.sh", destroy="./drop-vm.sh"))

Each batch still gets a machine nobody used before, set up exactly as the
Docker host is (`host.provision`), and it is destroyed after the batch
(after its run is exported, or what a failed run left is salvaged).

`SshHosts`: `create` is a command run here (bash) that makes a new machine
and prints its address, `[user@]host[:port]`, on its first line, and may
print the machine's SSH host public keys (`ssh-ed25519 AAAA...`) on the
following lines. With a key, every connection is pinned to it; without one
the first key seen is accepted and recorded (trust on first use). `destroy`
is a command run here after the batch, with the address in
$SAVANA_LAB_HOST. A pool of machines made in advance works too: `create`
hands out the next one and `destroy` retires it.

`AwsHosts`: the `aws` CLI with its own configured credentials makes an EC2
instance per batch (Canonical's Ubuntu 24.04 unless `ami` names another).
Its SSH host key and a login key are generated here for that one instance
and handed to it in its user data, so the connection is pinned from its
first byte and no key pair is registered in the account. The instance
terminates when it powers off: at the host's expiry deadline, or 4 hours
after it boots even if this driver is gone; and it is terminated after its
batch. Its security group must let this machine reach port 22.

The machine is Ubuntu 24.04 with systemd. What the Docker image installs
(packages and the pinned AgentDojo venv, `BOOTSTRAP`) is installed on it
unless it is already there. Commands run as root: as the login user with
passwordless sudo when that is not root. As with every host, a secret only
ever travels on a command's stdin: the SSH command line carries the script
and non-secret variables, never a key.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import json
from pathlib import Path
import re
import shlex
import shutil
import time

from .host import DockerHost, HostError, provision, utc_now
from .shell import CommandFailed

RUNTIME_VERSION = "0.1.35"
# The host image's packages (hostimg/Dockerfile) a machine may lack; systemd, dbus and sudo are a machine's own.
PACKAGES = ("python3 python3-venv python3-pip ca-certificates binutils acl iproute2 procps curl sudo less tcpdump "
            "strace")
BOOTSTRAP = r"""set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends @PACKAGES@
python3 -m venv /opt/savana-bench-venv
/opt/savana-bench-venv/bin/pip install -q --no-cache-dir -r /root/requirements-agentdojo.txt
""".replace("@PACKAGES@", PACKAGES)
RUNTIME_CHECK = r"""set -e
test "$(/opt/savana-bench-venv/bin/python -c 'import importlib.metadata as m; print(m.version("agentdojo"))' \
  2>/dev/null)" = @VERSION@
for command in systemctl tcpdump strace setfacl ss; do command -v "$command" >/dev/null; done
test -d /run/systemd/system
""".replace("@VERSION@", RUNTIME_VERSION)
# Canonical's public pointer to its current Ubuntu 24.04 image.
UBUNTU_AMI = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
ADDRESS = re.compile(r"(?:(?P<user>[a-z_][a-z0-9._-]{0,31})@)?(?P<host>[A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:]+\])"
                     r"(?::(?P<port>[0-9]{1,5}))?")
HOST_KEY = re.compile(r"(ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-rsa)"
                      r" [A-Za-z0-9+/]+={0,3}")


# -- what a run records: which hosts its batches get --------------------
@dataclass(frozen=True)
class DockerHosts:
    """A privileged container on this machine (the default)."""
    kind: str = "docker"


@dataclass(frozen=True)
class SshHosts:
    create: str
    destroy: str
    identity: str | None = None
    user: str = "root"
    kind: str = "ssh"


@dataclass(frozen=True)
class AwsHosts:
    region: str
    security_group: str
    subnet: str | None = None
    instance_type: str = "c7i.xlarge"
    ami: str | None = None
    profile: str | None = None
    volume_gb: int = 40
    public_ip: bool = True
    kind: str = "aws"


def host_spec(value):
    """A host spec (DockerHosts, SshHosts, AwsHosts) from itself, its record
    in run.json, or None (the Docker default)."""
    if value is None:
        return DockerHosts()
    if isinstance(value, (DockerHosts, SshHosts, AwsHosts)):
        spec = value
    elif isinstance(value, dict) and value.get("kind") in ("docker", "ssh", "aws"):
        cls = {"docker": DockerHosts, "ssh": SshHosts, "aws": AwsHosts}[value["kind"]]
        known = {f.name for f in fields(cls)}
        if set(value) - known:
            raise HostError(f"unknown {value['kind']} host options: {', '.join(sorted(set(value) - known))}")
        spec = cls(**value)
    else:
        raise HostError("a host is DockerHosts(), SshHosts(...) or AwsHosts(...)")
    if isinstance(spec, SshHosts) and not (spec.create.strip() and spec.destroy.strip()):
        raise HostError("SSH hosts need a create and a destroy command: every batch gets a new machine")
    if isinstance(spec, AwsHosts) and not (re.fullmatch(r"[a-z]{2}(-[a-z]+)+-[0-9]", spec.region)
                                           and spec.security_group.startswith("sg-")
                                           and type(spec.volume_gb) is int and 20 <= spec.volume_gb <= 500):
        raise HostError("AWS hosts need a region (us-east-1), a security group (sg-...) and 20-500 GB")
    return spec


def spec_record(spec):
    return asdict(host_spec(spec))


def make_host(spec, *, shell, workdir, label, sleep=time.sleep, now=utc_now):
    """The host for one batch (`label` names it: the batch)."""
    spec = host_spec(spec)
    if isinstance(spec, DockerHosts):
        return DockerHost(shell, workdir=workdir, sleep=sleep, now=now)
    if isinstance(spec, SshHosts):
        return SshHost(shell, workdir=workdir, label=label, create=spec.create, destroy=spec.destroy,
                       identity=spec.identity, user=spec.user, sleep=sleep, now=now)
    return AwsHost(shell, workdir=workdir, label=label, spec=spec, sleep=sleep, now=now)


# -- a machine over SSH -------------------------------------------------
class SshHost:
    kind = "ssh"
    marker = "ssh-disposable-machine"

    def __init__(self, shell, *, workdir, label, create=None, destroy=None, identity=None, user="root",
                 sleep=time.sleep, now=utc_now, ssh_wait=600):
        self.shell, self.workdir, self.label = shell, Path(workdir), label
        self.create_command, self.destroy_command = create, destroy
        self.identity = str(Path(identity).expanduser()) if identity else None
        self.default_user, self.sleep, self.now, self.ssh_wait = user, sleep, now, ssh_wait
        self.user = self.host = self.port = None
        self.pinned, self.fingerprints, self.repo, self.dir = False, [], None, None

    # -- the machine the hosts run on -------------------------------------
    def prepare(self, repo):
        self.repo = Path(repo)
        if shutil.which("ssh") is None:
            raise HostError("no ssh client on this machine")

    # -- one host --------------------------------------------------------
    def fresh(self, stage_tar, bin_tar):
        self.dir = self._new_dir()
        self._create()
        self._wait_for_ssh()
        self._bootstrap()
        return provision(self, stage_tar, bin_tar, kind=self.marker, what="machine")

    def _new_dir(self):
        """Where this machine's known_hosts (and an EC2 instance's keys) live."""
        root = self.workdir / "hosts"
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
        for n in range(100):
            path = root / f"{self.label}-{stamp}" if n == 0 else root / f"{self.label}-{stamp}-{n}"
            try:
                path.mkdir(mode=0o700)
                return path
            except FileExistsError:
                continue
        raise HostError("no fresh host directory")

    def _create(self):
        try:
            out = self.shell.run(["bash", "-c", self.create_command], timeout=1800).out
        except CommandFailed as error:
            raise HostError(f"the create command failed: {error}") from None
        lines = [line.strip() for line in out.splitlines() if line.strip()]
        self._connect_to(lines[0] if lines else "", [line for line in lines[1:] if HOST_KEY.match(line)])

    def _connect_to(self, address, host_keys):
        match = ADDRESS.fullmatch(address)
        if match is None or (match["port"] and not 0 < int(match["port"]) < 65536):
            raise HostError(f"the create command printed no address ([user@]host[:port]) on its first line: "
                            f"{address[:80]!r}")
        self.user, self.host = match["user"] or self.default_user, match["host"]
        self.port = int(match["port"]) if match["port"] else None
        known = self.dir / "known_hosts"
        bare = self.host.strip("[]")
        name = bare if self.port in (None, 22) else f"[{bare}]:{self.port}"
        known.write_text("".join(f"{name} {HOST_KEY.match(key).group(0)}\n" for key in host_keys))
        known.chmod(0o600)
        self.pinned = bool(host_keys)
        # Every option in one file, so a logged command shows what runs on the host.
        options = dict(HostName=bare, User=self.user, Port=self.port or 22, BatchMode="yes", ConnectTimeout=20,
                       ServerAliveInterval=15, ServerAliveCountMax=8, UserKnownHostsFile=f'"{known}"',
                       GlobalKnownHostsFile="/dev/null", LogLevel="ERROR",
                       StrictHostKeyChecking="yes" if self.pinned else "accept-new")
        if self.identity:
            options.update(IdentityFile=f'"{self.identity}"', IdentitiesOnly="yes")
        config = self.dir / "ssh_config"
        config.write_text("Host h\n" + "".join(f"  {k} {v}\n" for k, v in options.items()))
        config.chmod(0o600)
        self.shell.log.write(f"host {self.address()} " + ("pinned to its host key" if self.pinned else
                                                          "with no host key given: trust on first use"))

    def address(self):
        return f"{self.user}@{self.host}" + (f":{self.port}" if self.port else "")

    def ssh_argv(self, remote, *, stdin=False):
        """ssh to this host (its options in its own ssh_config); stdin only when it carries something."""
        return ["ssh", "-F", str(self.dir / "ssh_config"), *([] if stdin else ["-n"]), "h", "--", remote]

    def _as_root(self, script, env=None):
        """The remote command line: `script` under bash as root, with `env`
        (never a secret) set for it."""
        words = ([] if self.user == "root" else ["sudo", "-n"]) + (
            ["env", *(f"{k}={v}" for k, v in env.items())] if env else []) + ["bash", "-c", script]
        return " ".join(shlex.quote(w) for w in words)

    def _wait_for_ssh(self):
        waited = 0
        while True:
            result = self.shell.run(self.ssh_argv("true"), check=False, quiet=True, timeout=60)
            if result.code == 0:
                break
            if waited >= self.ssh_wait:
                raise HostError(f"{self.address()} did not answer over SSH in {self.ssh_wait}s: "
                                f"{(result.err or result.out).strip()[-200:]}")
            self.sleep(5)
            waited += 5
        listed = self.shell.run(["ssh-keygen", "-l", "-f", str(self.dir / "known_hosts")], check=False, quiet=True)
        self.fingerprints = [line.split()[1] for line in listed.out.splitlines() if len(line.split()) > 1]
        self.shell.log.write(f"host key {', '.join(self.fingerprints) or 'unknown'}"
                             + ("" if self.pinned else " (accepted on first use)"))

    def _bootstrap(self):
        # A machine that is still booting (cloud-init) holds the package lock.
        self.exec("command -v cloud-init >/dev/null && cloud-init status --wait >/dev/null; true", timeout=900)
        if self.exec(RUNTIME_CHECK, check=False, quiet=True).code == 0:
            self.shell.log.write("runtime already installed")
            return
        if self.repo is None:
            raise HostError("prepare(repo) before fresh(): the bootstrap installs the repository's requirements")
        self.put(self.repo / "experiments" / "requirements-agentdojo.txt", "/root/requirements-agentdojo.txt")
        try:
            self.exec(BOOTSTRAP, timeout=1800)
            self.exec(RUNTIME_CHECK, quiet=True)
        except CommandFailed as error:
            raise HostError(f"could not install the runtime on {self.address()}: {error}") from None

    def exec(self, script, *, env=None, input=None, timeout=600, check=True, quiet=False):
        """`bash -c script` as root on the host; `env` adds variables to that
        one command (never a secret: a secret goes on `input`)."""
        return self.shell.run(self.ssh_argv(self._as_root(script, env), stdin=input is not None), input=input,
                              timeout=timeout, check=check, quiet=quiet)

    def detach(self, script):
        remote = (("sudo -n " if self.user != "root" else "") + "setsid -f bash -c " + shlex.quote(script)
                  + " >/dev/null 2>&1 </dev/null")
        self.shell.run(self.ssh_argv(remote))

    def put(self, local, remote):
        """A local file to `remote` on the host (gzip on the wire, root-only on arrival)."""
        self.shell.pipe(["gzip", "-c", str(local)],
                        self.ssh_argv(self._as_root(f"umask 077; gunzip > {shlex.quote(remote)}"), stdin=True),
                        timeout=3600)

    def copy_out(self, directory, entry, destination):
        """Copy `directory/entry` from the host into `destination` (a tar stream, as before)."""
        Path(destination).mkdir(parents=True, exist_ok=True)
        self.shell.pipe(self.ssh_argv(self._as_root(f"tar -C {shlex.quote(directory)} -cf - {shlex.quote(entry)}")),
                        ["tar", "-C", str(destination), "-xf", "-"], timeout=3600)

    def alive(self):
        if self.host is None:
            return False
        return self.shell.run(self.ssh_argv("true"), check=False, quiet=True, timeout=60).code == 0

    def describe(self):
        return dict(kind=self.kind, address=None if self.host is None else self.address(),
                    host_key=self.fingerprints, pinned=self.pinned)

    def release(self):
        """Destroy the machine (the destroy command, given its address)."""
        if self.host is None:
            return None
        address, self.host = self.address(), None
        result = self.shell.run(["bash", "-c", self.destroy_command], env=dict(SAVANA_LAB_HOST=address),
                                timeout=1800, check=False)
        return dict(kind=self.kind, address=address, destroyed=result.code == 0)


# -- an EC2 instance ----------------------------------------------------
class AwsHost(SshHost):
    kind = "aws"
    marker = "aws-ec2-disposable-instance"

    def __init__(self, shell, *, workdir, label, spec, sleep=time.sleep, now=utc_now, ssh_wait=600):
        super().__init__(shell, workdir=workdir, label=label, user="ubuntu", sleep=sleep, now=now, ssh_wait=ssh_wait)
        self.spec, self.instance, self.ami = spec, None, spec.ami

    def prepare(self, repo):
        super().prepare(repo)
        if shutil.which("aws") is None or shutil.which("ssh-keygen") is None:
            raise HostError("AWS hosts need the aws CLI (with credentials) and ssh-keygen on this machine")

    def aws(self, *argv, check=True, quiet=False, timeout=600):
        base = ["aws"] + (["--profile", self.spec.profile] if self.spec.profile else []) + [
            "--region", self.spec.region]
        return self.shell.run(base + list(argv), check=check, quiet=quiet, timeout=timeout)

    def _create(self):
        """run-instances with this instance's own host and login keys in its user data."""
        for name in ("host_key", "login_key"):
            self.shell.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"savana-lab-{name}",
                            "-f", str(self.dir / name)])
        host_public = (self.dir / "host_key.pub").read_text().strip()
        user_data = self.dir / "user-data.yaml"
        user_data.write_text(cloud_config((self.dir / "host_key").read_text(), host_public,
                                          (self.dir / "login_key.pub").read_text().strip()))
        user_data.chmod(0o600)
        (self.dir / "host_key").unlink()  # the instance's own copy is the only one needed
        if self.ami is None:
            self.ami = self.aws("ssm", "get-parameter", "--name", UBUNTU_AMI, "--query", "Parameter.Value",
                                "--output", "text").out.strip()
        volume = f"VolumeSize={self.spec.volume_gb},VolumeType=gp3,DeleteOnTermination=true"
        argv = ["ec2", "run-instances", "--image-id", self.ami, "--instance-type", self.spec.instance_type,
                "--count", "1", "--security-group-ids", self.spec.security_group,
                "--instance-initiated-shutdown-behavior", "terminate",
                "--metadata-options", "HttpTokens=required,HttpEndpoint=enabled",
                "--block-device-mappings", f"DeviceName=/dev/sda1,Ebs={{{volume}}}",
                "--user-data", f"file://{user_data}",
                "--tag-specifications",
                f"ResourceType=instance,Tags=[{{Key=Name,Value=savana-lab-{self.label}}},"
                f"{{Key=savana-lab,Value={self.label}}}]", "--output", "json"]
        if self.spec.subnet:
            argv += ["--subnet-id", self.spec.subnet]
        argv.append("--associate-public-ip-address" if self.spec.public_ip else "--no-associate-public-ip-address")
        launched = json.loads(self.aws(*argv).out)
        self.instance = launched["Instances"][0]["InstanceId"]
        self.shell.log.write(f"instance {self.instance}")
        try:
            self.aws("ec2", "wait", "instance-running", "--instance-ids", self.instance, timeout=900)
            found = json.loads(self.aws("ec2", "describe-instances", "--instance-ids", self.instance,
                                        "--output", "json").out)
            instance = found["Reservations"][0]["Instances"][0]
            ip = instance.get("PublicIpAddress") if self.spec.public_ip else instance.get("PrivateIpAddress")
            if not ip:
                raise HostError(f"instance {self.instance} has no {'public' if self.spec.public_ip else 'private'} IP")
            self.identity = str(self.dir / "login_key")
            self._connect_to(f"ubuntu@{ip}", [host_public])
        except BaseException:
            self.release()
            raise

    def describe(self):
        return dict(super().describe(), instance=self.instance, region=self.spec.region,
                    instance_type=self.spec.instance_type, ami=self.ami)

    def release(self):
        """Terminate the instance (its volume goes with it)."""
        if self.instance is None:
            return None
        instance, self.instance, self.host = self.instance, None, None
        result = self.aws("ec2", "terminate-instances", "--instance-ids", instance, "--output", "json",
                          check=False)
        return dict(kind=self.kind, instance=instance, terminated=result.code == 0)


def aws_leftovers(shell, *, region, profile=None, terminate=False):
    """EC2 instances a savana_lab driver made that still exist (a driver
    killed between launching one and terminating it): [(id, state, label)].
    With `terminate`, they are terminated."""
    base = ["aws"] + (["--profile", profile] if profile else []) + ["--region", region]
    found = json.loads(shell.run(base + [
        "ec2", "describe-instances", "--filters", "Name=tag-key,Values=savana-lab",
        "Name=instance-state-name,Values=pending,running,stopping,stopped", "--output", "json"], quiet=True).out)
    leftovers = [(i["InstanceId"], i["State"]["Name"],
                  next((t["Value"] for t in i.get("Tags", []) if t["Key"] == "savana-lab"), ""))
                 for r in found.get("Reservations", []) for i in r["Instances"]]
    if terminate and leftovers:
        shell.run(base + ["ec2", "terminate-instances", "--instance-ids", *(i for i, _, _ in leftovers),
                          "--output", "json"])
    return leftovers


def cloud_config(host_private, host_public, login_public):
    """User data: this instance's SSH host key (so the first connection is
    already pinned), the one login key, and a power-off 4 hours after boot
    (the instance terminates on power-off) whatever happens to the driver."""
    indented = "".join(f"    {line}\n" for line in host_private.strip().splitlines())
    return ("#cloud-config\n"
            "ssh_deletekeys: true\n"
            "ssh_genkeytypes: []\n"
            "ssh_keys:\n"
            "  ed25519_private: |\n" + indented +
            f"  ed25519_public: {host_public}\n"
            "ssh_authorized_keys:\n"
            f"  - {login_public}\n"
            "bootcmd:\n"
            "  - [shutdown, -P, '+240', savana-lab expiry]\n")
