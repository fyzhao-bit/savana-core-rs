"""One batch on one brand-new host: set it up, start the runner, wait, export.

The steps and the commands run on the host are planner-attempt.sh's,
run-batch-f5.sh's wait and planner-export.sh's. What changed is what
happens when a step fails: the batch stops there with the step's own error
(an installer that failed no longer goes on to the next step, and a failing
command inside a pipeline fails its step), and the model key reaches the
host only on `configure-model`'s stdin.
"""
from __future__ import annotations

import json
import time

from .shell import CommandFailed

VENV = "/opt/savana-bench-venv/bin/python"
ADMIN = "/usr/libexec/savana/savana-experiment-admin"
RUNS = "/var/lib/savana-benchmark/runs"
SERVICE = "savana-protected-experiment.service"
HARNESS_ENV = ("export PYTHONPATH=/opt/savana-protected/python:/opt/savana-protected/experiments "
               "PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1")


class AttemptFailed(RuntimeError):
    """The host could not be set up or started: no run exists."""


class RunFailed(RuntimeError):
    """The runner started but no complete run came out of it."""


class Batch:
    """`disposition` / `unconfined_write` (the floor experiment, planner-attempt-floor.sh) reach
    the deployment materializer through the installer's environment; the provisioned
    disposition is then checked against the request."""

    def __init__(self, host, *, key, capture=False, strace=False, disposition=None, unconfined_write=None,
                 sleep=time.sleep, clock=time.monotonic):
        self.host, self.key, self.capture, self.strace = host, key, capture, strace
        self.disposition, self.unconfined_write = disposition, unconfined_write
        self.sleep, self.clock = sleep, clock
        self.log = host.shell.log

    def step(self, what, script, **options):
        try:
            return self.host.exec(script, **options)
        except CommandFailed as error:
            raise AttemptFailed(f"{what}: {error}") from None

    def attempt(self, spec, stage_tar, bin_tar):
        """planner-attempt.sh: a fresh host, the kernel installed, the model key
        and an owner identity provisioned, the spec's drop-in written, the
        batch armed and the runner started."""
        try:
            self.host.fresh(stage_tar, bin_tar)
        except CommandFailed as error:
            raise AttemptFailed(f"fresh host: {error}") from None
        self.step("install", "cd /root && timeout 900 " + VENV + " /opt/savana-protected/deploy/linux/integration/"
                  "install.py --file-backed-integration --binaries /root/linux-b-bin --owner-control "
                  "--protected-experiment > /root/install.log 2>&1; code=$?; tail -1 /root/install.log; exit $code",
                  timeout=960, env=self.install_env())
        if self.disposition is not None:
            self.check_disposition()
        self.step("prepare-auth", f"{ADMIN} prepare-auth >/dev/null")
        self.configure_model()
        self.step("enroll", PROVISION, env=dict(PLANNER_SPEC=spec))
        status = self.step("status", f"{ADMIN} status", quiet=True).out
        checks = json.loads(status)
        failing = [k for k, v in checks["checks"].items() if not v]
        self.log.write(f"false checks: {failing} ready: {checks['ready_to_request_real_authentication']}")
        self.step("listeners", LISTENERS)
        if self.capture:
            # Request/status lines only; no bodies, capabilities or assertions are retained.
            self.host.detach(CAPTURE)
            self.sleep(1)
        if self.strace:
            for daemon in ("ingressd", "approvald", "kerneld"):
                self.host.detach(STRACE.replace("@DAEMON@", daemon))
            self.sleep(2)
        self.step("arm and start", START)

    def install_env(self):
        env = {}
        if self.disposition is not None:
            env["SAVANA_PROTECTED_EXPERIMENT_DISPOSITION"] = self.disposition
        if self.unconfined_write is not None:
            env["SAVANA_PROTECTED_EXPERIMENT_UNCONFINED_WRITE"] = self.unconfined_write
        return env or None

    def check_disposition(self):
        shown = self.step("disposition", DISPOSITION, quiet=True).out.split()
        self.log.write("disposition provisioned {} kernel {} unconfined {}".format(*shown))
        if shown[:2] != [self.disposition, self.disposition] or shown[2] != str(self.unconfined_write):
            raise AttemptFailed(f"the host provisioned {shown}, not disposition {self.disposition} "
                                f"unconfined {self.unconfined_write}")

    def configure_model(self):
        # The key goes on stdin (fd 3 for the admin tool), never in an argument or the environment.
        try:
            result = self.host.exec(f"exec 3<&0 0</dev/null; exec {ADMIN} configure-model --key-fd 3",
                                    input=self.key, quiet=True)
        except CommandFailed as error:
            raise AttemptFailed(f"configure-model: {error}") from None
        for line in (result.out + result.err).splitlines():
            if "encrypted media" not in line:
                self.log.write(line)

    def wait(self, *, start_timeout=600, run_timeout=2400, progress=None):
        """Wait for the run directory, then until its summary is written or
        the runner's service stops. `progress(done)` hears the number of
        episodes scored so far whenever it changes. Returns the run id."""
        deadline = self.clock() + start_timeout
        run = ""
        while not run:
            run = self.host.exec(f"ls -td {RUNS}/*/ 2>/dev/null | head -1", quiet=True).out.strip()
            if run:
                break
            if self.clock() > deadline:
                raise RunFailed(f"no run directory {start_timeout}s after the start")
            self.sleep(2)
        run_id = run.rstrip("/").rsplit("/", 1)[-1]
        deadline, scored, misses = self.clock() + run_timeout, None, 0
        while True:
            try:
                state = self.host.exec(WAIT_PROBE.replace("@RUN@", run_id), quiet=True, timeout=60).out.split()
                done, finished = int(state[0]), state[1] == "finished"
                misses = 0
            except (CommandFailed, IndexError, ValueError) as error:
                # One failed probe is not a failed run: the runner goes on regardless.
                misses += 1
                if misses >= 6:
                    raise RunFailed(f"the host stopped answering: {error}") from None
                self.sleep(10)
                continue
            if done != scored and progress is not None:
                progress(done)
            scored = done
            if finished:
                return run_id
            if self.clock() > deadline:
                raise RunFailed(f"the run did not finish in {run_timeout}s")
            self.sleep(10)

    def export(self, run_id, out):
        """planner-export.sh's export: the run directory and four listings."""
        out.mkdir(parents=True, exist_ok=True)
        self.host.copy_out(RUNS, run_id, out)
        self._listings(out, check=True)
        return out / run_id

    def salvage(self, out):
        """Keep what a run that did not finish left on its host: the batch then
        counts as incomplete, and is moved aside (never deleted) before it runs again."""
        out.mkdir(parents=True, exist_ok=True)
        run = self.host.exec(f"ls -td {RUNS}/*/ 2>/dev/null | head -1", check=False, quiet=True).out.strip()
        if run:
            self.host.copy_out(RUNS, run.rstrip("/").rsplit("/", 1)[-1], out)
        self._listings(out, check=False)

    def _listings(self, out, check):
        listings = {
            # Operator write-ahead journal: which signed commands exist and which got a kernel receipt.
            "operator-journal-listing.txt": 'cd /var/lib/savana-experiment-operator && for d in */; do '
                                            'printf "%s %s\\n" "${d%/}" "$(ls "$d" | tr "\\n" " ")"; done',
            "http-request-status-lines.txt": "cat /root/http-lines.txt 2>/dev/null || true",
            "runner-journal.txt": f"journalctl -u {SERVICE} --no-pager -o short-iso",
            # The deployment's provisioning profile (disposition, any unconfined write): digests only.
            "provisioning.json": "python3 -c 'import json; print(json.dumps(json.load(open("
                                 "\"/var/lib/savana-benchmark/operator-bindings.json\"))[\"provisioning\"], "
                                 "indent=1, sort_keys=True))'",
        }
        for name, script in listings.items():
            (out / name).write_text(self.host.exec(script, quiet=True, check=check).out)


# planner-attempt.sh's provisioning, as it ran there: an owner identity, the
# two committed software-benchmark drop-ins, and the spec's own drop-in.
PROVISION = r"""set -eo pipefail; cd /root; """ + HARNESS_ENV + r"""
""" + VENV + r""" -m savana_bench.benchmark_identity enroll | cut -c1-90
for s in auth:savana-experiment-auth launch:savana-protected-experiment; do d=/etc/systemd/system/${s#*:}.service.d; install -d -m 0755 $d; install -m 0644 /opt/savana-protected/experiments/deploy/software-benchmark-${s%%:*}.conf $d/90-software-benchmark.conf; done
printf "[Service]\nExecStart=\nExecStart=""" + VENV + r""" -m savana_bench.protected_launch --software-benchmark --planner-experiment %s\n" "$PLANNER_SPEC" > /etc/systemd/system/savana-protected-experiment.service.d/95-planner-experiment.conf; chmod 0644 /etc/systemd/system/savana-protected-experiment.service.d/95-planner-experiment.conf; systemctl daemon-reload; systemctl cat savana-protected-experiment.service | grep "^ExecStart=/"
"""
# What the deployment and the kernel were provisioned with (planner-attempt-floor.sh's check).
DISPOSITION = ("""python3 -c 'import json; b=json.load(open("/var/lib/savana-benchmark/operator-bindings.json")); """
               """k=json.load(open("/etc/savana/kerneld-bootstrap-v2.json")); print(b["provisioning"]["disposition"], """
               """k["policy_runtime"]["disposition"], b["provisioning"].get("unconfined_write"))'""")
LISTENERS = r"""ss -ltnp | grep -E "savana|python" | awk '{print $4, $6}' | sed 's/users:(("\([^"]*\)".*/\1/' | sort -u"""
START = r"""set -eo pipefail; cd /root; """ + HARNESS_ENV + r"""
""" + VENV + r""" -m savana_bench.benchmark_identity arm | python3 -c "import json,sys; d=json.load(sys.stdin); print(\"armed batch\", d[\"batch_id\"][:12], \"expires_ms\", d[\"expires_at_unix_ms\"])"
systemctl restart savana-experiment-auth.service; sleep 2; systemctl is-active savana-experiment-auth.service
""" + ADMIN + r""" start; date -u +%T"""
CAPTURE = (r"""tcpdump -i lo -l -A -s 512 "tcp port 8766 or tcp port 8767 or tcp port 8768" 2>/dev/null | """
           r"""grep --line-buffered -oE "(POST|GET) /[^ ]* HTTP/1.1|HTTP/1.1 [0-9]{3} [A-Za-z ]+" | """
           r"""while read -r l; do echo "$(date -u +%T.%N | cut -c1-12) $l"; done > /root/http-lines.txt""")
STRACE = (r"""strace -f -tt -s 32 -e trace=connect,accept4,sendto,recvfrom,sendmsg,recvmsg,read,write,close """
          r"""-o /root/@DAEMON@.trace -p $(systemctl show -p MainPID --value savana-@DAEMON@.service)""")
# Episodes scored so far, and whether the run is over: its summary is
# written, or the runner's service is no longer active.
WAIT_PROBE = (r"""R=""" + RUNS + r"""/@RUN@; n=$(grep -c '"kind":"episode_score"' $R/events.jsonl 2>/dev/null); """
              r"""if grep -q '"kind":"summary"' $R/events.jsonl 2>/dev/null || ! systemctl is-active -q """ + SERVICE +
              r"""; then echo "${n:-0} finished"; else echo "${n:-0} running"; fi""")
