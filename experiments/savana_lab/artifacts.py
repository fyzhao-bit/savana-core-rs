"""The prebuilt pieces every host gets, and the revision that built them.

A host runs the kernel binaries (deploy/linux/integration/build.py), the
`savana_core` wheel (maturin) and the structured-planning example
(`cargo build --example structured_plan_eval`). Building them takes about
twenty minutes, so they are built once per revision of the Rust sources and
kept in a store (`<workdir>/artifacts/<rev>/`) with a receipt of what built
them. A run may only stage a revision whose Rust sources (`RUST`) are those
the artifacts were built from: then the code a host runs is the code the
offline verifier replays.

A variant (`<rev>-<variant>/`) is a counterfactual build, e.g. the floor
experiment's kernel without its fail-closed floor: the revision with a patch
applied for the build only. Its receipt keeps the patch; a run uses a variant
only when it names it.
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import time

RUST = ("crates", "Cargo.toml", "Cargo.lock")
RECEIPT = "artifacts.json"


class ArtifactError(RuntimeError):
    pass


@dataclass(frozen=True)
class Artifacts:
    rev: str
    bin_tar: Path
    wheel: Path
    example: Path
    variant: str | None = None

    def digests(self):
        return {name: _sha256(path) for name, path in
                (("bin_tar", self.bin_tar), ("wheel", self.wheel), ("example", self.example))}

    def check_builds(self, git, stage_rev):
        """Refuse a staged revision whose Rust sources differ from the ones these were built from."""
        if not git.same_tree(self.rev, stage_rev, RUST):
            raise ArtifactError(f"the Rust sources changed between {self.rev[:7]} (artifacts) and "
                                f"{stage_rev[:7]} (stage): build artifacts for {stage_rev[:7]} first")


class Git:
    def __init__(self, shell, repo):
        self.shell, self.repo = shell, Path(repo)

    def __call__(self, *args, check=True):
        return self.shell.run(["git", "-C", str(self.repo), *args], check=check, quiet=True)

    def head(self):
        return self("rev-parse", "HEAD").out.strip()

    def resolve(self, rev):
        return self("rev-parse", "--verify", f"{rev}^{{commit}}").out.strip()

    def clean(self, paths):
        return not self("status", "--porcelain", "--", *paths).out.strip()

    def same_tree(self, a, b, paths):
        return self("diff", "--quiet", a, b, "--", *paths, check=False).code == 0


class ArtifactStore:
    def __init__(self, root):
        self.root = Path(root)

    def all(self):
        found = []
        for receipt in sorted(self.root.glob(f"*/{RECEIPT}")):
            value = json.loads(receipt.read_text())
            here = receipt.parent
            found.append((value, Artifacts(value["rev"], here / "linux-b-bin.tar", here / value["wheel"],
                                           here / "structured_plan_eval", value.get("variant"))))
        return found

    def for_stage(self, git, stage_rev, variant=None):
        """The newest stored artifacts (of `variant`; None: the plain build)
        whose Rust sources are `stage_rev`'s."""
        matches = [(value["created"], a) for value, a in self.all()
                   if a.variant == variant and git.same_tree(a.rev, stage_rev, RUST)]
        if not matches:
            kind = "" if variant is None else f" of variant {variant}"
            raise ArtifactError(f"no artifacts{kind} built from {stage_rev[:7]}'s Rust sources in {self.root}: "
                                "run `python -m savana_lab artifacts build` (about 20 minutes)")
        return max(matches, key=lambda m: m[0])[1]

    def _target(self, rev, variant):
        if variant is not None and not variant.replace("-", "").isalnum():
            raise ArtifactError("a variant name is letters, digits and -")
        target = self.root / (rev if variant is None else f"{rev}-{variant}")
        if (target / RECEIPT).exists():
            raise ArtifactError(f"artifacts for {target.name[:7]}{'' if variant is None else '-' + variant} "
                                f"are already stored at {target}")
        partial = self.root / f".{target.name}.partial"
        shutil.rmtree(partial, ignore_errors=True)
        partial.mkdir(parents=True)
        return target, partial

    def adopt(self, *, rev, bin_tar, wheel, example, note, variant=None):
        """Keep artifacts built elsewhere (`note` says by what) under `rev`.
        Their receipt records each file's digest; nothing is rebuilt."""
        target, partial = self._target(rev, variant)
        shutil.copyfile(bin_tar, partial / "linux-b-bin.tar")
        shutil.copyfile(wheel, partial / Path(wheel).name)
        shutil.copyfile(example, partial / "structured_plan_eval")
        (partial / "structured_plan_eval").chmod(0o755)
        return self._seal(partial, target, dict(rev=rev, wheel=Path(wheel).name, origin="adopted", note=note,
                                                variant=variant,
                                                sources={"bin_tar": str(bin_tar), "wheel": str(wheel),
                                                         "example": str(example)}))

    def build(self, shell, git, *, python, jobs=2, offline=False, target_dir=None, patch=None, variant=None):
        """Build all three from HEAD. The Rust sources must be committed (the
        receipt names a revision, so the build must be that revision's). With
        `patch` (and a `variant` name) the patch is applied to the working
        tree for the build only, and undone after it."""
        if (patch is None) != (variant is None):
            raise ArtifactError("a patched build is a variant: give both patch and variant")
        if not git.clean(RUST):
            raise ArtifactError("uncommitted changes under crates/ or Cargo.*: commit them first")
        rev, repo = git.head(), git.repo
        target, partial = self._target(rev, variant)
        if patch is not None:
            shutil.copyfile(patch, partial / "variant.patch")
            git("apply", "--check", str(patch))
            git("apply", str(patch))
        try:
            steps = self._build(shell, repo, partial, python, jobs, offline, target_dir)
        finally:
            if patch is not None:
                git("apply", "-R", str(partial / "variant.patch"))
        if git.head() != rev or not git.clean(RUST):
            raise ArtifactError("HEAD or the Rust sources changed during the build; the build is discarded")
        return self._seal(partial, target, dict(rev=rev, wheel=steps.pop(), origin="built", steps=steps,
                                                jobs=jobs, offline=offline, variant=variant))

    def _build(self, shell, repo, partial, python, jobs, offline, target_dir):
        target_dir = Path(target_dir or self.root / "target-sdk")
        steps, offline_flag = [], ["--offline"] if offline else []
        started = time.monotonic()
        # Kernel binaries: the integration profile, workspace packages cleaned
        # first, with a build receipt of every source hash.
        shell.run(["python3", repo / "deploy/linux/integration/build.py", "--output", partial / "linux-b-bin",
                   *offline_flag], cwd=repo, timeout=5400, stream=True)
        shell.run(["tar", "-cf", partial / "linux-b-bin.tar", "-C", partial, "linux-b-bin.build.json",
                   "linux-b-bin"])
        shutil.rmtree(partial / "linux-b-bin")
        steps.append(dict(step="binaries", seconds=round(time.monotonic() - started)))
        # The SDK wheel: abi3 (Python >= 3.12), release, locked.
        started = time.monotonic()
        shell.run([python, "-m", "maturin", "build", "--release", "--locked", *offline_flag, "--interpreter",
                   python, "-o", partial / "wheel"], cwd=repo / "crates/savana-core-py", timeout=5400, stream=True,
                  env=dict(CARGO_TARGET_DIR=str(target_dir), CARGO_BUILD_JOBS=str(jobs)))
        wheels = sorted((partial / "wheel").glob("*.whl"))
        if len(wheels) != 1:
            raise ArtifactError(f"expected one wheel, found {[w.name for w in wheels]}")
        wheels[0].rename(partial / wheels[0].name)
        (partial / "wheel").rmdir()
        steps.append(dict(step="wheel", seconds=round(time.monotonic() - started)))
        # The structured-planning example (agentd's test-support feature).
        started = time.monotonic()
        shell.run(["cargo", "build", f"-j{jobs}", "--locked", *offline_flag, "-p", "savana-agentd", "--features",
                   "test-support", "--example", "structured_plan_eval"], cwd=repo, timeout=5400, stream=True,
                  env=dict(CARGO_INCREMENTAL="0"))
        shutil.copyfile(repo / "target/debug/examples/structured_plan_eval", partial / "structured_plan_eval")
        (partial / "structured_plan_eval").chmod(0o755)
        steps.append(dict(step="example", seconds=round(time.monotonic() - started)))
        return steps + [wheels[0].name]

    def _seal(self, partial, target, receipt):
        receipt["created"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        receipt["sha256"] = {name: _sha256(partial / name) for name in
                             ("linux-b-bin.tar", receipt["wheel"], "structured_plan_eval")}
        if (partial / "variant.patch").exists():
            receipt["patch_sha256"] = _sha256(partial / "variant.patch")
        (partial / RECEIPT).write_text(json.dumps(receipt, indent=1, sort_keys=True) + "\n")
        partial.rename(target)
        return Artifacts(receipt["rev"], target / "linux-b-bin.tar", target / receipt["wheel"],
                         target / "structured_plan_eval", receipt.get("variant"))


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()
