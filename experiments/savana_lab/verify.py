"""Offline verification of an exported batch (`savana_bench.planner_verify`).

The verifier must run the code the host ran: the harness at the staged
revision (a `git archive` of it, never the working tree, since the run's
manifest pins every module's digest) and the `savana` / `savana_core`
packages from the staged wheel. A failed verification is an error, never
a line in a log: nothing counts a batch the verifier did not pass.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import zipfile

from .results import verification


class VerificationFailed(RuntimeError):
    pass


class Verifier:
    def __init__(self, shell, git, workdir, python):
        self.shell, self.git, self.workdir, self.python = shell, git, Path(workdir), str(python)

    def tree(self, rev):
        """`<workdir>/verify/<rev>/experiments`: the harness and its pinned
        third-party data (AutoDojo caches) at `rev`."""
        root = self.workdir / "verify" / rev
        experiments = root / "experiments"
        if (experiments / "savana_bench").is_dir() and (experiments / "third_party").is_dir():
            return experiments
        partial = self.workdir / "verify" / f".{rev}.partial"
        shutil.rmtree(partial, ignore_errors=True)
        partial.mkdir(parents=True)
        self.shell.pipe(["git", "-C", str(self.git.repo), "archive", rev, "experiments/savana_bench",
                         "experiments/third_party"], ["tar", "-x", "-C", str(partial)])
        shutil.rmtree(root, ignore_errors=True)
        partial.rename(root)
        return experiments

    def packages(self, wheel):
        """The staged wheel, unpacked once: the `savana` and `savana_core` the host imported."""
        wheel = Path(wheel)
        # Every build of the same version has the same file name: key by content.
        root = self.workdir / "verify" / f"wheel-{_sha256(wheel)[:16]}"
        if (root / "savana_core").is_dir():
            return root
        partial = root.with_name(root.name + ".partial")
        shutil.rmtree(partial, ignore_errors=True)
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(partial)
        partial.rename(root)
        return root

    def verify(self, batch_dir, run_dir, rev, wheel):
        """Verify one exported run; writes `offline-verification.json` (the
        verifier's output) and `.err` next to it, as before. Raises
        VerificationFailed unless the verifier passed it."""
        batch_dir = Path(batch_dir)
        tree = self.tree(rev)
        packages = self.packages(wheel)
        result = self.shell.run([self.python, "-m", "savana_bench.planner_verify", str(run_dir)], cwd=tree,
                                env=dict(PYTHONPATH=f".:{packages}"), check=False, quiet=True, timeout=1800)
        (batch_dir / "offline-verification.json").write_text(result.out)
        (batch_dir / "offline-verification.err").write_text(result.err)
        passed = verification(batch_dir)
        if result.code != 0 or passed is None:
            tail = " | ".join(result.err.strip().splitlines()[-3:]) or "no output"
            raise VerificationFailed(f"{batch_dir.name}: offline verification failed: {tail}")
        return passed


def summary_line(value):
    groups = value.get("groups", {})
    published = sum(g.get("published", 0) for g in groups.values())
    utility = sum(g.get("utility_successes", 0) for g in groups.values())
    return (f"verified {value['episodes_verified']} episodes: {published} published, {utility} useful, "
            f"{value['unauthorized_provider_attempts']} unauthorized")


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()
