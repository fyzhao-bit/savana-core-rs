"""Running commands: the one place a process starts.

Every command goes through a `Shell`, so a test can see exactly what a run
would issue (`tests/test_savana_lab.py` uses a recording fake). A secret is
only ever passed on a command's stdin, never in its arguments or
environment, and any text a command prints is redacted before it is logged.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import subprocess
import threading
import time


class CommandFailed(RuntimeError):
    def __init__(self, argv, code, out, err):
        tail = (err or out).strip().splitlines()[-3:]
        super().__init__(f"{_show(argv)} exited {code}: {' | '.join(tail)}")
        self.argv, self.code, self.out, self.err = argv, code, out, err


@dataclass
class Result:
    code: int
    out: str = ""
    err: str = ""


def _show(argv):
    shown = " ".join(" ".join(argv).split())
    return shown if len(shown) <= 160 else shown[:157] + "..."


class Log:
    """A batch's or a run's text log. Lines are timestamped; secrets are
    replaced before anything is written."""

    def __init__(self, path=None, secrets=(), echo=False):
        self.path, self.secrets, self.echo = path, [s for s in secrets if s], echo

    def redact(self, text):
        for secret in self.secrets:
            text = text.replace(secret, "[redacted]")
        return text

    def write(self, text):
        text = self.redact(text)
        stamp = time.strftime("%H:%M:%S", time.gmtime())
        lines = "".join(f"{stamp} {line}\n" for line in text.splitlines() or [""])
        if self.path is not None:
            with open(self.path, "a") as handle:
                handle.write(lines)
        if self.echo:
            print(lines, end="", flush=True)


class Shell:
    """Runs commands for real. `log` (a Log) gets each command and its output."""

    def __init__(self, log=None):
        self.log = log or Log()

    def run(self, argv, *, input=None, env=None, cwd=None, timeout=None, check=True, quiet=False, stream=False):
        """Run `argv`; `input` (str or bytes) goes to its stdin. Output is
        captured as text and logged unless `quiet`; with `stream` (a long
        build) each line is logged as it comes, stderr merged into stdout."""
        argv = [str(a) for a in argv]
        self.log.write(f"$ {_show(argv)}")
        if stream:
            return self._stream(argv, env=env, cwd=cwd, timeout=timeout, check=check)
        data = input.encode() if isinstance(input, str) else input
        try:
            done = subprocess.run(argv, input=data, stdin=None if data is not None else subprocess.DEVNULL,
                                  capture_output=True, env=_env(env), cwd=cwd, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            out = (error.stdout or b"").decode(errors="replace")
            raise CommandFailed(argv, "timeout", out, f"timed out after {timeout}s") from None
        result = Result(done.returncode, done.stdout.decode(errors="replace"), done.stderr.decode(errors="replace"))
        if not quiet:
            for text in (result.out, result.err):
                if text.strip():
                    self.log.write(text.rstrip("\n"))
        if check and result.code != 0:
            raise CommandFailed(argv, result.code, self.log.redact(result.out), self.log.redact(result.err))
        return result

    def _stream(self, argv, *, env, cwd, timeout, check):
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, env=_env(env), cwd=cwd)
        expired = threading.Event()
        timer = threading.Timer(timeout, lambda: (expired.set(), process.kill())) if timeout else None
        if timer is not None:
            timer.start()
        lines = []
        try:
            for raw in process.stdout:
                line = raw.decode(errors="replace").rstrip("\n")
                lines.append(line)
                self.log.write(line)
            code = process.wait()
        finally:
            if timer is not None:
                timer.cancel()
            process.stdout.close()
        out = self.log.redact("\n".join(lines))
        if expired.is_set():
            raise CommandFailed(argv, "timeout", out, f"timed out after {timeout}s")
        if check and code != 0:
            raise CommandFailed(argv, code, out, "")
        return Result(code, out, "")

    def pipe(self, first, second, *, cwd=None, timeout=None):
        """`first | second`, both checked (a tar stream out of the host)."""
        first, second = [str(a) for a in first], [str(a) for a in second]
        self.log.write(f"$ {_show(first)} | {_show(second)}")
        producer = subprocess.Popen(first, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
        try:
            consumer = subprocess.run(second, stdin=producer.stdout, capture_output=True, cwd=cwd, timeout=timeout)
        finally:
            producer.stdout.close()
        err = producer.stderr.read().decode(errors="replace")
        producer.stderr.close()
        code = producer.wait(timeout=timeout)
        if code != 0 or consumer.returncode != 0:
            raise CommandFailed(first + ["|"] + second, code or consumer.returncode,
                                consumer.stdout.decode(errors="replace"), err + consumer.stderr.decode(errors="replace"))
        return Result(0)

    def spawn(self, argv, *, log_path):
        """Start a long-lived process detached from this one (dockerd)."""
        argv = [str(a) for a in argv]
        self.log.write(f"$ {_show(argv)} &")
        with open(log_path, "ab") as out:
            subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                             start_new_session=True)


def _env(extra):
    if extra is None:
        return None
    env = dict(os.environ)
    env.update(extra)
    return env
