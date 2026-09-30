#!/usr/bin/env python3
"""Build Linux B binaries serially, without enabling Mac authority in daemons."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

RUNTIME_BINARIES = {
    "savana-kerneld": ["savana-kerneld"],
    "savana-agentd": ["savana-agentd", "savana-ownerctl"],
    "savana-ingressd": ["savana-ingressd", "savana-parser-worker"],
    "savana-approvald": ["savana-approvald", "savana-approvalctl"],
    "savana-execd": ["savana-execd", "savana-connector-worker"],
    "savana-platform-identity": ["savana-worker-sandbox", "savana-linux-identity-broker"],
    "savana-policy-core": ["savana-linux-integration-manifest", "savana-systemd-agentd-network-policy-v2"],
}


def clean_workspace(repo):
    """Never reuse workspace artifacts from a different checkout at /workspace.

    Docker mounts can have the same logical path and older mtimes than another
    worktree's artifacts. Keep downloaded third-party builds but rebuild every
    workspace package, including shared protocol/browser assets.
    """
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked", "--offline"],
        cwd=repo, text=True))
    members = set(metadata["workspace_members"])
    names = sorted(p["name"] for p in metadata["packages"] if p["id"] in members)
    if not names or len(names) != len(members):
        raise RuntimeError("incomplete workspace metadata")
    command = ["cargo", "clean"]
    for name in names:
        command += ["--package", name]
    subprocess.run(command, cwd=repo, check=True)


def source_snapshot(repo):
    paths = {repo / "Cargo.toml", repo / "Cargo.lock"}
    paths.update((repo / "crates").glob("*/Cargo.toml"))
    paths.update((repo / "crates").glob("*/build.rs"))
    for source in (repo / "crates").glob("*/src"):
        paths.update(p for p in source.rglob("*") if p.is_file())
    if any(p.is_symlink() for p in paths):
        raise RuntimeError("symlinked build source")
    return {str(p.relative_to(repo)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(paths)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux" or args.output.exists() or args.output.is_symlink():
        raise SystemExit("Linux and a new output directory required")
    repo = Path(__file__).resolve().parents[3]
    target = Path(os.environ.get("CARGO_TARGET_DIR", str(repo / "target"))).resolve()
    base = ["cargo", "build", "--locked", "--jobs", "1"]
    if args.offline:
        base.append("--offline")
    before = source_snapshot(repo)
    clean_workspace(repo)
    # Generator only emits new signed data. Its feature must not flow into the
    # separate runtime build. Never use --workspace --all-features here.
    subprocess.run(base + ["-p", "savana-kerneld", "--features", "macos-development-authority",
        "--bin", "savana-development-build-inputs"], cwd=repo, check=True)
    generator = (target / "debug/savana-development-build-inputs").read_bytes()
    for package, binaries in RUNTIME_BINARIES.items():
        command = base + ["-p", package, "--features", "savana-policy-core/filesystem-integration-authority"]
        if package != "savana-policy-core":
            command += ["-p", "savana-policy-core"]
        if package == "savana-kerneld":
            command += ["--features", "linux-file-backed-integration"]
        for binary in binaries:
            command += ["--bin", binary]
        subprocess.run(command, cwd=repo, check=True)
    args.output.mkdir(mode=0o700)
    generator_path = args.output / "savana-development-build-inputs"
    generator_path.write_bytes(generator)
    generator_path.chmod(0o755)
    for binaries in RUNTIME_BINARIES.values():
        for binary in binaries:
            shutil.copyfile(target / "debug" / binary, args.output / binary)
            (args.output / binary).chmod(0o755)
    # Strip only exported copies; keep Cargo's debug cache and debug_assertions.
    for path in args.output.iterdir():
        subprocess.run(["strip", "--strip-debug", str(path)], check=True)
    if before != source_snapshot(repo):
        raise SystemExit("source changed during build; exported binaries must not be deployed")
    receipt = {"profile": "file-backed-integration", "workspace_cache_reused": False,
               "sources": before, "binaries": {
                   p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(args.output.iterdir())}}
    args.output.with_suffix(".build.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print("Linux B binaries built; no installation or authentication performed.")


if __name__ == "__main__":
    main()
