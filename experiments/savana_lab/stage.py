"""What a host gets at /opt/savana-protected (run-batch-f5.sh's staging).

The repository's `deploy` and `experiments` at the staged revision (never
the working tree), the suite's committed tool catalog as the one the host
serves, the SDK wheel unpacked into `python/`, and the structured-planning
example at `bin/structured_plan_eval`.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import zipfile

CATALOGS = Path("deploy/linux/integration")


def build_stage(shell, repo, rev, suite, artifacts, workdir, catalog_suffix="", catalog_variant=None):
    """Write `workdir/stage-opt.tar` for one suite; returns (tar path, a one-line description).
    `catalog_variant` (the floor experiment) is a catalog file served instead of the
    committed one, e.g. a write descriptor without its intent-flow validator."""
    workdir = Path(workdir)
    root = workdir / "stage-opt"
    shutil.rmtree(root, ignore_errors=True)
    stage = root / "savana-protected"
    (stage / "python").mkdir(parents=True)
    shell.pipe(["git", "-C", str(repo), "archive", rev, "deploy", "experiments"], ["tar", "-x", "-C", str(stage)])
    shutil.rmtree(stage / "experiments" / "results", ignore_errors=True)
    # A host serves exactly one AgentDojo suite: that suite's committed catalog
    # (`-masked`: the model tools on the model codec, for extract='masked').
    catalog = stage / CATALOGS / f"read-tool-catalog-v04-{suite}{catalog_suffix}.json"
    if not catalog.is_file():
        raise FileNotFoundError(f"no committed catalog {catalog.name} at {rev[:7]}")
    shutil.copyfile(catalog_variant or catalog, stage / CATALOGS / "read-tool-catalog-v04.json")
    with zipfile.ZipFile(artifacts.wheel) as wheel:
        wheel.extractall(stage / "python")
    for info in (stage / "python").glob("*.dist-info"):
        shutil.rmtree(info)
    (stage / "bin").mkdir()
    shutil.copyfile(artifacts.example, stage / "bin" / "structured_plan_eval")
    (stage / "bin" / "structured_plan_eval").chmod(0o755)
    for cache in sorted(root.rglob("__pycache__"), reverse=True):
        shutil.rmtree(cache, ignore_errors=True)
    tar = workdir / "stage-opt.tar"
    shell.run(["tar", "-cf", str(tar), "-C", str(root), "savana-protected"])
    example = hashlib.sha256((stage / "bin" / "structured_plan_eval").read_bytes()).hexdigest()[:16]
    variant = "" if catalog_variant is None else (
        f" catalog-variant={hashlib.sha256(Path(catalog_variant).read_bytes()).hexdigest()[:16]}")
    return tar, f"staged {rev[:7]} suite={suite}{catalog_suffix}{variant} example={example}"
