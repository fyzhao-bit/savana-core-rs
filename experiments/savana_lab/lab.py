"""The lab: where runs, results and built artifacts live, and the run handle.

    lab = Lab()                                   # this checkout, its results directory, ~/.savana-lab
    run = lab.create(make_plan("u9c", U9, benign()))
    run.start(background=True)                    # a detached driver; returns at once
    print(run.status())                           # from this or any later process
    run.stop()                                    # after the batch that is running
    run.report().utility()

A run is recorded in `<results>/_lab/<name>/`: `run.json` (its plan, the
revision it stages and the artifacts it uses, fixed when it is created),
`progress.jsonl` (every step the driver took), `driver.log` and one log per
batch attempt under `logs/`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from . import balance as balances
from .artifacts import RUST, ArtifactError, ArtifactStore, Git
from .driver import LabError, Lock, drive, now
from .host import NAME as HOST_NAME
from .plan import Plan
from .results import ABSENT, VERIFIED, batch_state, rows, task_rows
from .shell import Log, Shell
from .verify import Verifier

REPO = Path(__file__).resolve().parents[2]
RESULTS = REPO / "experiments" / "results" / "local-container-20260930"
# What must be committed before a run is created: the staged revision is HEAD.
CODE = (*RUST, "deploy", "experiments")


def _default_workdir():
    return Path(os.environ.get("SAVANA_LAB_WORKDIR", Path.home() / ".savana-lab"))


@dataclass
class Lab:
    repo: Path = REPO
    results: Path = RESULTS
    workdir: Path = field(default_factory=_default_workdir)
    # The Python that verifies runs (AgentDojo 0.1.35 installed): `setup()` makes one.
    python: Path | None = None
    echo: bool = False

    def __post_init__(self):
        self.repo, self.results, self.workdir = Path(self.repo), Path(self.results), Path(self.workdir)
        if self.python is None and os.environ.get("SAVANA_LAB_PYTHON"):
            self.python = Path(os.environ["SAVANA_LAB_PYTHON"])

    # -- the parts, each replaceable in a test ---------------------------
    def shell(self, log=None):
        return Shell(log or Log(echo=self.echo))

    def git(self, shell=None):
        return Git(shell or self.shell(), self.repo)

    def host(self, shell, spec=None, label="batch"):
        """The host for one batch: `spec` is the run's (DockerHosts() by default)."""
        from .remote import make_host
        return make_host(spec, shell=shell, workdir=self.workdir, label=label)

    def verifier(self, shell):
        return Verifier(shell, self.git(shell), self.workdir, self.verify_python())

    def balance(self, key):
        return balances.deepseek_balance(key)

    def store(self):
        return ArtifactStore(self.workdir / "artifacts")

    def lock_path(self):
        """One driver per machine, whatever its workdir: every host has the same name."""
        return Path(tempfile.gettempdir()) / f"savana-lab-{HOST_NAME}.lock"

    def verify_python(self):
        python = self.python or self.workdir / "venv" / "bin" / "python"
        if not Path(python).exists():
            raise LabError(f"no verification Python at {python}: run `python -m savana_lab setup` "
                           "(or pass python= / set SAVANA_LAB_PYTHON)")
        return Path(python)

    def setup(self):
        """A venv for verification and builds: AgentDojo 0.1.35 and maturin."""
        venv = self.workdir / "venv"
        shell = self.shell(Log(echo=True))
        if not (venv / "bin" / "python").exists():
            shell.run([sys.executable if sys.version_info >= (3, 12) else "python3.12", "-m", "venv", venv])
        shell.run([venv / "bin" / "python", "-m", "pip", "install", "-q", "-r",
                   Path(__file__).parent / "requirements.txt"], timeout=1800)
        return venv / "bin" / "python"

    # -- runs ------------------------------------------------------------
    def create(self, plan, *, capture=False, strace=False, disposition=None, unconfined_write=None,
               catalog_variant=None, artifacts_variant=None, host=None):
        """Record a new run of `plan`, staging HEAD with stored artifacts built
        from HEAD's Rust sources. Creating a run that exists with the same
        plan returns it (running it resumes it).

        `host` says where each batch's brand-new host comes from:
        DockerHosts() on this machine (the default), SshHosts(...) or
        AwsHosts(...) (`remote.py`). It is recorded with the run, so a
        resumed run gets the same kind of host.

        The floor experiment's options: `disposition` ("require_approval" or
        "permit") and `unconfined_write` (the one write tool shipped without
        its intent-flow validator) go to the deployment materializer;
        `catalog_variant` (a file, kept with the run) is served instead of the
        suite's committed catalog; `artifacts_variant` names a counterfactual
        build (`artifacts build --patch ... --variant ...`)."""
        run = Run(self, plan.name)
        if run.exists():
            if run.plan.to_json() != plan.to_json():
                raise LabError(f"run {plan.name} exists with a different plan; pick another name")
            return run
        taken = [b.name for b in plan.batches if batch_state(self.results, b.name) != ABSENT]
        if taken:
            raise LabError(f"the results already hold {', '.join(taken[:3])}{'...' if len(taken) > 3 else ''} "
                           "from an earlier run: pick another run name")
        git = self.git()
        if not git.clean(CODE):
            raise LabError("uncommitted changes under crates/, Cargo.*, deploy/ or experiments/: commit first "
                           "(a run stages a commit, and its verifier replays that commit)")
        if disposition not in (None, "require_approval", "permit"):
            raise LabError("disposition is require_approval or permit")
        from .host import HostError
        from .remote import spec_record
        try:
            hosts = spec_record(host)
        except (HostError, TypeError) as error:
            raise LabError(str(error)) from None
        stage_rev = git.head()
        artifacts = self.store().for_stage(git, stage_rev, artifacts_variant)
        run.dir.mkdir(parents=True)
        floor = {}
        if catalog_variant is not None:
            data = Path(catalog_variant).read_bytes()
            json.loads(data)
            (run.dir / "catalog-variant.json").write_bytes(data)
            floor["catalog_variant_sha256"] = hashlib.sha256(data).hexdigest()
        meta = dict(name=plan.name, created=now(), stage_rev=stage_rev, results=str(self.results),
                    artifacts=dict(rev=artifacts.rev, variant=artifacts.variant, sha256=artifacts.digests()),
                    capture=capture, strace=strace, disposition=disposition, unconfined_write=unconfined_write,
                    **floor, host=hosts, plan=plan.to_json())
        (run.dir / "run.json").write_text(json.dumps(meta, indent=1) + "\n")
        return run

    def open(self, name):
        run = Run(self, name)
        if not run.exists():
            raise LabError(f"no run {name} under {self.results / '_lab'}")
        return run

    def runs(self):
        root = self.results / "_lab"
        found = [Run(self, p.parent.name) for p in root.glob("*/run.json")] if root.is_dir() else []
        return sorted(found, key=lambda r: r.meta()["created"])

    def stop(self):
        """Ask the running driver to stop before its next batch."""
        self.workdir.mkdir(parents=True, exist_ok=True)
        (self.workdir / "STOP").write_text(now() + "\n")

    def artifacts_for(self, run):
        """The artifacts `run` was created with, unchanged since."""
        recorded = run.meta()["artifacts"]
        for _, artifacts in self.store().all():
            if artifacts.rev == recorded["rev"] and artifacts.variant == recorded.get("variant"):
                if artifacts.digests() != recorded["sha256"]:
                    raise ArtifactError(f"the stored artifacts for {recorded['rev'][:7]} changed since "
                                        f"run {run.name} was created")
                return artifacts
        raise ArtifactError(f"run {run.name}'s artifacts ({recorded['rev'][:7]}) are no longer stored")

    def report(self, *names):
        from .report import Report
        return Report.load(self, *names)


class Run:
    def __init__(self, lab, name):
        self.lab, self.name = lab, name
        self.dir = lab.results / "_lab" / name

    def exists(self):
        return (self.dir / "run.json").is_file()

    def meta(self):
        return json.loads((self.dir / "run.json").read_text())

    @property
    def plan(self):
        return Plan.from_json(self.meta()["plan"])

    def next_log(self, batch):
        logs = self.dir / "logs"
        logs.mkdir(exist_ok=True)
        attempt = 1 + len(list(logs.glob(f"{batch}.*.log")))
        return logs / f"{batch}.{attempt}.log"

    # -- driving ---------------------------------------------------------
    def start(self, *, background=False, deadline=None, keys=None):
        """Drive the plan here (returns done / stopped / failed), or in a
        detached process that outlives this one (returns its pid). Model keys
        come from each provider's environment variable ($DEEPSEEK_API_KEY,
        ...) or `keys` ({provider: key}) and reach a background driver through
        its environment only."""
        from .driver import model_keys
        keys = model_keys(self.plan) if keys is None else keys
        stop = self.lab.workdir / "STOP"
        if stop.exists():
            stop.unlink()
        if not background:
            return drive(self.lab, self, keys=keys, deadline=deadline)
        if self.alive():
            raise LabError(f"run {self.name}'s driver is already running")
        with Lock(self.lab.lock_path()):
            pass   # another run's driver holds it: say so here, not only in the child's output
        argv = [sys.executable, "-m", "savana_lab", "--results", str(self.lab.results), "--workdir",
                str(self.lab.workdir)]
        if self.lab.python is not None:
            argv += ["--python", str(self.lab.python)]
        argv += ["resume", self.name]
        if deadline is not None:
            argv += ["--deadline", str(deadline)]
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join([str(self.lab.repo / "experiments"), env.get("PYTHONPATH", "")])
        from savana_bench.chat_models import KEY_VARIABLES
        for name, value in keys.items():
            env[KEY_VARIABLES.get(name, name.upper().replace("-", "_") + "_API_KEY")] = value
        with open(self.dir / "driver.out", "ab") as out:
            child = subprocess.Popen(argv, cwd=self.lab.repo, env=env, stdout=out, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL, start_new_session=True)
        (self.dir / "driver.pid").write_text(f"{child.pid}\n")
        return child.pid

    def alive(self):
        try:
            pid = int((self.dir / "driver.pid").read_text())
            return b"savana_lab" in Path(f"/proc/{pid}/cmdline").read_bytes()
        except (OSError, ValueError):
            return False

    def stop(self):
        self.lab.stop()

    def wait(self, poll=10):
        while self.alive():
            time.sleep(poll)
        return self.status()

    # -- reading ---------------------------------------------------------
    def progress(self, follow=False, poll=5):
        """Every progress event so far; with `follow`, keep yielding new ones
        while the driver runs."""
        path, seen = self.dir / "progress.jsonl", 0
        while True:
            lines = path.read_text().splitlines() if path.exists() else []
            for line in lines[seen:]:
                yield json.loads(line)
            seen = len(lines)
            if not follow or not self.alive():
                return
            time.sleep(poll)

    def status(self):
        return Status.of(self)

    def report(self):
        from .report import Report
        return Report(self.lab, [b.name for b in self.plan.batches], name=self.name)


@dataclass
class Status:
    run: str
    alive: bool
    batches: dict
    current: str | None
    episodes: tuple | None
    last: dict | None
    failure: str | None
    balance: tuple | None
    utility: dict
    stopping: bool = False
    setup_failures: dict = field(default_factory=dict)
    host: dict | None = None
    unreleased: list = field(default_factory=list)

    @classmethod
    def of(cls, run):
        events = list(run.progress())
        batches = {b.name: batch_state(run.lab.results, b.name) for b in run.plan.batches}
        current = episodes = failure = host = None
        setup, unreleased = {}, []
        balances_seen = [e["usd"] for e in events if e["event"] == "balance" and e.get("usd") is not None]
        for event in events:
            if event["event"] == "batch_started":
                current, episodes, host = event["batch"], (0, event["cases"]), None
            elif event["event"] == "host" and event["batch"] == current:
                host = event
            elif event["event"] == "host_released" and (event.get("error") or False in (
                    event.get("destroyed"), event.get("terminated"))):
                # A remote host still there costs money: say so until someone looks.
                unreleased.append(f"{event['batch']}: {event.get('instance') or event.get('address')} "
                                  f"({event.get('error') or 'destroy failed'})")
            elif event["event"] == "episodes" and event["batch"] == current:
                episodes = (event["done"], event["of"])
            elif event["event"] in ("verified", "failed") and event.get("batch") == current:
                current = episodes = None
            if event["event"] == "setup_failures":
                setup[event["batch"]] = f"{event['count']}/{event['of']} ({', '.join(event['errors'])})"
            if event["event"] == "failed":
                failure = f"{event.get('batch')}: {event['error']}"
            elif event["event"] == "run_started":
                failure = None
        utility = {}
        for name, state in batches.items():
            if state != VERIFIED:
                continue
            for row in task_rows(rows(run.lab.results, name)):
                ok, total = utility.get(row["suite"], (0, 0))
                utility[row["suite"]] = (ok + (row.get("utility") is True), total + 1)
        alive = run.alive()
        return cls(run.name, alive, batches, current if alive else None, episodes if alive else None,
                   events[-1] if events else None, failure,
                   (balances_seen[0], balances_seen[-1]) if balances_seen else None, utility,
                   alive and (run.lab.workdir / "STOP").exists(), setup, host if alive else None, unreleased)

    def __str__(self):
        verified = sum(s == VERIFIED for s in self.batches.values())
        lines = [f"{self.run}: {verified}/{len(self.batches)} batches verified, driver "
                 f"{'running' if self.alive else 'not running'}"]
        if self.current:
            done = f" ({self.episodes[0]}/{self.episodes[1]} episodes scored)" if self.episodes else ""
            where = ""
            if self.host and self.host.get("kind") != "docker":
                where = " on " + " ".join(str(self.host[k]) for k in ("kind", "instance", "address")
                                          if self.host.get(k))
            lines.append(f"  running {self.current}{done}{where}")
        for item in self.unreleased:
            lines.append(f"  host NOT released: {item}; check it (python -m savana_lab aws-leftovers ...)")
        if self.stopping:
            lines.append("  stop requested: the driver stops after the batch that is running")
        if self.last:
            lines.append(f"  last: {self.last['t']} {self.last['event']}"
                         + "".join(f" {k}={v}" for k, v in self.last.items() if k not in ("t", "event")))
        if self.failure:
            lines.append(f"  failed: {self.failure}")
        elif not self.alive and self.last and self.last["event"] not in ("done", "stopped", "failed"):
            lines.append("  the driver exited before the plan ended: resume the run")
        if self.balance:
            lines.append(f"  model balance {self.balance[0]} -> {self.balance[1]} USD")
        if self.utility:
            ok = sum(v[0] for v in self.utility.values())
            total = sum(v[1] for v in self.utility.values())
            parts = ", ".join(f"{s} {v[0]}/{v[1]}" for s, v in sorted(self.utility.items()))
            lines.append(f"  utility so far (verified batches): {ok}/{total} ({parts})")
        if self.setup_failures:
            lines.append("  episodes that failed at setup (they measured nothing): "
                         + "; ".join(f"{b} {v}" for b, v in self.setup_failures.items()))
        others = {s for s in self.batches.values() if s not in (VERIFIED, ABSENT)}
        if others:
            lines.append("  not verified: " + ", ".join(f"{n} ({s})" for n, s in self.batches.items()
                                                         if s in others))
        return "\n".join(lines)
