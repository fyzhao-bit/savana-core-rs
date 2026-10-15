"""A brand-new disposable host per batch.

Here the host is a privileged Docker container with systemd as PID 1 on this
machine (docs/verification/local-container-experiment-20260930.md); a host
on another machine, over SSH or as an EC2 instance, is `remote.py`'s. Every
host is set up the same way (`provision`): the expiry guard and the
disposable-host marker the installer requires, then the staged tree and the
kernel binaries.

Every command a host runs is the one the earlier shell drivers ran
(fresh-host.sh, planner-attempt.sh), issued from Python.

What a batch needs of its host (`Batch`, the driver): `prepare(repo)` once
per batch on this machine, `fresh(stage_tar, bin_tar)` (a brand-new host,
set up; returns its expiry deadline), `exec`, `detach`, `put`, `copy_out`,
`alive`, `describe()` (what it was, for the record) and `release()` after
the batch (a remote host is destroyed then; this one is kept until the next
batch replaces it, as before).
"""
from __future__ import annotations

import datetime
import os
from pathlib import Path
import shutil
import time

from .shell import CommandFailed

NAME = "savana-b"
IMAGE = "savana-b-host:24.04"
RECIPE = Path(__file__).parent / "hostimg"
# Extra CA certificates the image trusts (the build machine's egress proxy).
CA_DIR = Path("/usr/local/share/ca-certificates")
# A host powers itself off after this long, whatever happens to its driver.
EXPIRY = datetime.timedelta(hours=4)


class HostError(RuntimeError):
    pass


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def provision(host, stage_tar, bin_tar, *, kind, what="container"):
    """fresh-host.sh's setup of a booted host: rshared root, the absolute
    expiry guard, the disposable-host marker (naming the kind of host), the
    payload. Returns the expiry deadline."""
    deadline = (host.now() + EXPIRY).strftime("%Y-%m-%d %H:%M:%S UTC")
    host.exec(EXPIRY_SCRIPT.replace("@DEADLINE@", deadline).replace("@HOST@", kind).replace("@WHAT@", what))
    host.put(stage_tar, "/root/stage-opt.tar")
    host.put(bin_tar, "/root/linux-b-bin.tar")
    host.exec("set -e; cd /opt && tar -xf /root/stage-opt.tar && cd /root && tar -xf /root/linux-b-bin.tar"
              " && chown -R root:root /opt/savana-protected /root/linux-b-bin && chmod 700 /root/linux-b-bin")
    host.exec("findmnt -n -o PROPAGATION /; systemctl is-active savana-acceptance-expiry.timer; "
              "systemctl list-timers --no-legend savana-acceptance-expiry.timer | cut -c1-40")
    host.shell.log.write(f"deadline {deadline}")
    return deadline


class DockerHost:
    kind = "docker"

    def __init__(self, shell, *, workdir, name=NAME, image=IMAGE, ca_dir=CA_DIR, sleep=time.sleep, now=utc_now,
                 euid=os.geteuid):
        self.shell, self.workdir, self.name, self.image = shell, Path(workdir), name, image
        self.ca_dir, self.sleep, self.now, self.euid = Path(ca_dir), sleep, now, euid

    # -- the machine the hosts run on -------------------------------------
    def prepare(self, repo):
        self.ensure_daemon()
        self.ensure_image(repo)

    def ensure_daemon(self, wait=60):
        info = self.shell.run(["docker", "info"], check=False, quiet=True)
        if info.code == 0:
            return
        if self.euid() != 0:
            # Only root can start a daemon of its own (a session VM without
            # one); any other user needs the machine's, and the right to use it.
            said = (info.err or info.out).strip().splitlines()
            raise HostError("docker info failed" + (f" ({said[-1].strip()})" if said else "")
                            + ": start Docker (sudo service docker start) and let this user use it "
                              "(sudo usermod -aG docker $USER, then log in again)")
        self.shell.spawn(["dockerd"], log_path=self.workdir / "dockerd.log")
        for _ in range(wait):
            self.sleep(1)
            if self.shell.run(["docker", "info"], check=False, quiet=True).code == 0:
                return
        raise HostError(f"dockerd did not come up in {wait}s (see {self.workdir / 'dockerd.log'})")

    def ensure_image(self, repo, rebuild=False):
        """Build the host image unless it exists: Ubuntu 24.04, systemd, and
        the AgentDojo venv at /opt/savana-bench-venv."""
        if not rebuild and self.shell.run(["docker", "image", "inspect", self.image], check=False,
                                          quiet=True).code == 0:
            return
        context = self.workdir / "hostimg"
        shutil.rmtree(context, ignore_errors=True)
        (context / "certs").mkdir(parents=True)
        shutil.copy(RECIPE / "Dockerfile", context / "Dockerfile")
        shutil.copy(Path(repo) / "experiments" / "requirements-agentdojo.txt", context)
        for cert in sorted(self.ca_dir.glob("*.crt")) if self.ca_dir.is_dir() else ():
            shutil.copy(cert, context / "certs")
        self.shell.run(["docker", "build", "-t", self.image, str(context)], timeout=3600)

    # -- one host --------------------------------------------------------
    def remove(self):
        self.shell.run(["docker", "rm", "-f", self.name], check=False, quiet=True)

    def fresh(self, stage_tar, bin_tar):
        """fresh-host.sh: boot, rshared root, expiry guard, marker, payload."""
        self.remove()
        self.shell.run(["docker", "run", "-d", "--name", self.name, "--privileged", "--network", "host",
                        "--cgroupns=host", "-v", "/sys/fs/cgroup:/sys/fs/cgroup:rw", "--tmpfs", "/run",
                        "--tmpfs", "/run/lock", "--tmpfs", "/tmp", self.image])
        state = ""
        for _ in range(30):
            state = self.shell.run(["docker", "exec", self.name, "systemctl", "is-system-running"],
                                   check=False, quiet=True).out.strip()
            if state in ("running", "degraded"):
                break
            self.sleep(1)
        self.shell.log.write(f"systemd: {state}")
        return provision(self, stage_tar, bin_tar, kind="docker-privileged-container-on-ephemeral-session-vm")

    def put(self, local, remote):
        self.shell.run(["docker", "cp", str(local), f"{self.name}:{remote}"])

    def describe(self):
        return dict(kind=self.kind, container=self.name, image=self.image)

    def release(self):
        """Kept until the next batch's `fresh` replaces it (it powers itself off at its deadline)."""
        return None

    def exec(self, script, *, env=None, input=None, timeout=600, check=True, quiet=False):
        """`bash -c script` on the host; `env` adds variables to that one
        command (never a secret: a secret goes on `input`)."""
        argv = ["docker", "exec"]
        if input is not None:
            argv.append("-i")
        for key, value in (env or {}).items():
            argv += ["-e", f"{key}={value}"]
        return self.shell.run(argv + [self.name, "bash", "-c", script], input=input, timeout=timeout,
                              check=check, quiet=quiet)

    def detach(self, script):
        self.shell.run(["docker", "exec", "-d", self.name, "bash", "-c", script])

    def copy_out(self, directory, entry, destination):
        """Copy `directory/entry` from the host into `destination` (a tar stream, as before)."""
        Path(destination).mkdir(parents=True, exist_ok=True)
        self.shell.pipe(["docker", "exec", self.name, "tar", "-C", directory, "-cf", "-", entry],
                        ["tar", "-C", str(destination), "-xf", "-"])

    def alive(self):
        try:
            return self.shell.run(["docker", "inspect", "-f", "{{.State.Running}}", self.name],
                                  quiet=True).out.strip() == "true"
        except CommandFailed:
            return False


# fresh-host.sh's in-host part. systemd leaves mount propagation to container
# managers; a real host boots rshared. The timer powers the host off at an
# absolute deadline; the marker says what kind of host this is.
EXPIRY_SCRIPT = r"""set -e
mount --make-rshared /
umask 077
printf '[Unit]\nDescription=Disposable Savana B test host expiry (@WHAT@ poweroff)\n[Service]\nType=oneshot\nExecStart=/usr/bin/systemctl poweroff --no-block\n' > /etc/systemd/system/savana-acceptance-expiry.service
printf '[Unit]\nDescription=Absolute expiry for the disposable Savana B test @WHAT@\n[Timer]\nOnCalendar=@DEADLINE@\nPersistent=false\nAccuracySec=1s\n' > /etc/systemd/system/savana-acceptance-expiry.timer
chmod 0644 /etc/systemd/system/savana-acceptance-expiry.*
systemctl daemon-reload && systemctl start savana-acceptance-expiry.timer
printf 'profile=file-backed-integration\nhost=@HOST@\ncreated=%s\n' "$(date -u +%FT%TZ)" > /run/savana-file-backed-disposable
chmod 0600 /run/savana-file-backed-disposable
"""
