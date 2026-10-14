"""A brand-new disposable host per batch: a privileged Docker container with
systemd as PID 1 (docs/verification/local-container-experiment-20260930.md).

Every command a host runs is the one the earlier shell drivers ran
(fresh-host.sh, planner-attempt.sh), issued from Python.
"""
from __future__ import annotations

import datetime
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


class DockerHost:
    def __init__(self, shell, *, workdir, name=NAME, image=IMAGE, ca_dir=CA_DIR, sleep=time.sleep,
                 now=lambda: datetime.datetime.now(datetime.timezone.utc)):
        self.shell, self.workdir, self.name, self.image = shell, Path(workdir), name, image
        self.ca_dir, self.sleep, self.now = Path(ca_dir), sleep, now

    # -- the machine the hosts run on -------------------------------------
    def ensure_daemon(self, wait=60):
        if self.shell.run(["docker", "info"], check=False, quiet=True).code == 0:
            return
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
        deadline = (self.now() + EXPIRY).strftime("%Y-%m-%d %H:%M:%S UTC")
        self.exec(EXPIRY_SCRIPT.replace("@DEADLINE@", deadline))
        self.shell.run(["docker", "cp", str(stage_tar), f"{self.name}:/root/stage-opt.tar"])
        self.shell.run(["docker", "cp", str(bin_tar), f"{self.name}:/root/linux-b-bin.tar"])
        self.exec("set -e; cd /opt && tar -xf /root/stage-opt.tar && cd /root && tar -xf /root/linux-b-bin.tar"
                  " && chown -R root:root /opt/savana-protected /root/linux-b-bin && chmod 700 /root/linux-b-bin")
        self.exec("findmnt -n -o PROPAGATION /; systemctl is-active savana-acceptance-expiry.timer; "
                  "systemctl list-timers --no-legend savana-acceptance-expiry.timer | cut -c1-40")
        self.shell.log.write(f"deadline {deadline}")
        return deadline

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
printf '[Unit]\nDescription=Disposable Savana B test host expiry (container poweroff)\n[Service]\nType=oneshot\nExecStart=/usr/bin/systemctl poweroff --no-block\n' > /etc/systemd/system/savana-acceptance-expiry.service
printf '[Unit]\nDescription=Absolute expiry for the disposable Savana B test container\n[Timer]\nOnCalendar=@DEADLINE@\nPersistent=false\nAccuracySec=1s\n' > /etc/systemd/system/savana-acceptance-expiry.timer
chmod 0644 /etc/systemd/system/savana-acceptance-expiry.*
systemctl daemon-reload && systemctl start savana-acceptance-expiry.timer
printf 'profile=file-backed-integration\nhost=docker-privileged-container-on-ephemeral-session-vm\ncreated=%s\n' "$(date -u +%FT%TZ)" > /run/savana-file-backed-disposable
chmod 0600 /run/savana-file-backed-disposable
"""
