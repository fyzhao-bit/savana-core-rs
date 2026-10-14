"""Running a plan: one batch after another, each on a brand-new host.

The loop is f5-chunk.sh's. One driver at a time (a lock: there is one host
name); a stop file ends it before the next batch; a verified batch is
skipped, so running a plan again resumes it; an interrupted batch's
directory is moved aside, never deleted; the model balance is checked
before every batch. Unlike the shell driver, a batch whose offline
verification fails stops the run (it used to print VERIFY_FAILED and go
on), and a complete but unverified batch is never run again by itself: it
is re-verified (`savana_lab verify`) or moved aside on purpose (`rerun`).

Everything the driver does is appended to `<run dir>/progress.jsonl`, which
`Run.status()` reads, from this process or any other.
"""
from __future__ import annotations

import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal

from . import balance as balances
from .batch import AttemptFailed, Batch, RunFailed
from .config import runner_cases
from .results import INCOMPLETE, UNVERIFIED, VERIFIED, batch_state, move_aside
from .shell import CommandFailed, Log, Shell
from .stage import build_stage
from .verify import VerificationFailed, summary_line

KEY_VARIABLE = "DEEPSEEK_API_KEY"


class LabError(RuntimeError):
    pass


class Interrupted(BaseException):
    pass


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Progress:
    def __init__(self, path, log=None):
        self.path, self.log = Path(path), log

    def emit(self, event, **fields):
        record = dict(t=now(), event=event, **fields)
        with open(self.path, "a") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
        if self.log is not None:
            self.log.write(" ".join([event] + [f"{k}={v}" for k, v in fields.items()]))
        return record


class Lock:
    """The one-driver-at-a-time lock (flock, released when the process ends)."""

    def __init__(self, path):
        self.path = Path(path)

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(self.path, "a+")
        try:
            fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.handle.seek(0)
            holder = self.handle.read().strip() or "another driver"
            self.handle.close()
            raise LabError(f"a driver is already running ({holder}); one host, one driver") from None
        self.handle.seek(0)
        self.handle.truncate()
        self.handle.write(f"pid {os.getpid()}\n")
        self.handle.flush()
        return self

    def __exit__(self, *_):
        self.handle.close()


def drive(lab, run, *, key=None, deadline=None, clock=None, sleep=None):
    """Run `run`'s plan to its end, a stop, a low balance or a failure.
    Returns the final progress event's name: done, stopped or failed."""
    import time
    clock = clock or time.monotonic
    sleep = sleep or time.sleep
    key = key if key is not None else os.environ.get(KEY_VARIABLE, "")
    if not key:
        raise LabError(f"the model key is read from ${KEY_VARIABLE}; it is not set")
    log = Log(run.dir / "driver.log", secrets=[key], echo=lab.echo)
    progress = Progress(run.dir / "progress.jsonl", log)
    started = clock()

    def interrupt(signum, _frame):
        raise Interrupted(signal.Signals(signum).name)

    with Lock(lab.workdir / "driver.lock"):
        previous = {s: signal.signal(s, interrupt) for s in (signal.SIGTERM, signal.SIGHUP)}
        try:
            return _drive(lab, run, key, deadline, clock, sleep, log, progress, started)
        except Interrupted as signal_name:
            progress.emit("stopped", reason=f"signal {signal_name}")
            return "stopped"
        finally:
            for s, handler in previous.items():
                signal.signal(s, handler)


def _drive(lab, run, key, deadline, clock, sleep, log, progress, started):
    meta = run.meta()
    stage_rev, artifacts = meta["stage_rev"], lab.artifacts_for(run)
    progress.emit("run_started", run=run.name, stage=stage_rev[:12], artifacts=artifacts.rev[:12],
                  batches=len(run.plan))
    stop_file = lab.workdir / "STOP"
    for batch in run.plan.batches:
        if stop_file.exists():
            progress.emit("stopped", reason="stop requested")
            return "stopped"
        if deadline is not None and clock() - started > deadline:
            progress.emit("stopped", reason=f"deadline {deadline}s reached")
            return "stopped"
        state = batch_state(lab.results, batch.name)
        if state == VERIFIED:
            progress.emit("skipped", batch=batch.name, reason="verified")
            continue
        if state == UNVERIFIED:
            progress.emit("failed", batch=batch.name,
                          error="its complete run is not verified: `savana_lab verify` it, or `rerun` it")
            return "failed"
        if state == INCOMPLETE:
            moved = move_aside(lab.results, batch.name)
            progress.emit("moved_aside", batch=batch.name, to=str(moved.relative_to(lab.results)))
        status = lab.balance(key)
        progress.emit("balance", state=status[0], usd=status[1])
        if not balances.enough(status):
            progress.emit("stopped", reason="model balance low or unavailable")
            return "stopped"
        batch_log = Log(run.next_log(batch.name), secrets=[key], echo=False)
        shell = lab.shell(batch_log)
        host = lab.host(shell)
        runner, runner_started = None, False
        try:
            host.ensure_daemon()
            host.ensure_image(lab.repo)
            variant = run.dir / "catalog-variant.json" if meta.get("catalog_variant_sha256") else None
            if variant is not None and hashlib.sha256(variant.read_bytes()).hexdigest() != meta["catalog_variant_sha256"]:
                raise ValueError("the run's catalog variant changed since the run was created")
            tar, staged = build_stage(shell, lab.repo, stage_rev, batch.suite, artifacts, lab.workdir,
                                      batch.config().catalog_suffix(), variant)
            batch_log.write(staged)
            cases = len(runner_cases(batch.spec))
            progress.emit("batch_started", batch=batch.name, suite=batch.suite, cases=cases, spec=batch.spec)
            runner = Batch(host, key=key, capture=meta.get("capture", False), strace=meta.get("strace", False),
                           disposition=meta.get("disposition"), unconfined_write=meta.get("unconfined_write"),
                           sleep=sleep, clock=clock)
            runner.attempt(batch.spec, tar, artifacts.bin_tar)
            runner_started = True
            progress.emit("runner_started", batch=batch.name)
            run_id = runner.wait(progress=lambda done: progress.emit("episodes", batch=batch.name, done=done,
                                                                     of=cases))
            run_dir = runner.export(run_id, lab.results / batch.name)
            progress.emit("exported", batch=batch.name, run_id=run_id)
            value = lab.verifier(shell).verify(lab.results / batch.name, run_dir, stage_rev, artifacts.wheel)
            progress.emit("verified", batch=batch.name, summary=summary_line(value))
        except (AttemptFailed, RunFailed, VerificationFailed, CommandFailed, OSError, ValueError) as error:
            progress.emit("failed", batch=batch.name, error=f"{type(error).__name__}: {error}")
            if runner_started and not (lab.results / batch.name).exists():
                try:
                    runner.salvage(lab.results / batch.name)
                    progress.emit("salvaged", batch=batch.name)
                except (CommandFailed, OSError) as lost:
                    progress.emit("salvage_failed", batch=batch.name, error=str(lost))
            return "failed"
    progress.emit("done", run=run.name)
    return "done"
