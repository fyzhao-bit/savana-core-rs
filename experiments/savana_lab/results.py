"""The results directory: one subdirectory per batch, as the shell drivers left it.

    <results>/<batch>/<run-id>/events.jsonl, summary.json, completion.json, publication-NN.jsonl
    <results>/<batch>/offline-verification.json (+ .err), runner-journal.txt, provisioning.json, ...
    <results>/_interrupted/<batch>-<epoch>/   a batch moved aside before it was run again
    <results>/_lab/<run>/                     what savana_lab records about a run

Evidence is moved aside, never deleted.
"""
from __future__ import annotations

import json
from pathlib import Path
import time

VERIFIED, UNVERIFIED, INCOMPLETE, ABSENT = "verified", "unverified", "incomplete", "absent"


def run_dirs(batch_dir):
    return sorted(p.parent for p in Path(batch_dir).glob("*/events.jsonl"))


def verification(batch_dir):
    """The offline verifier's result for a batch, or None unless it passed."""
    path = Path(batch_dir) / "offline-verification.json"
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    return value if type(value) is dict and value.get("audit_consistent") is True else None


def batch_state(results, name):
    """VERIFIED: its verifier passed. UNVERIFIED: a complete run was exported
    but its verification is missing or failed (re-verify it; running it again
    would spend the models again). INCOMPLETE: a directory without a complete
    run (an interrupted batch). ABSENT: never exported."""
    batch = Path(results) / name
    if not batch.exists():
        return ABSENT
    if verification(batch) is not None:
        return VERIFIED
    runs = run_dirs(batch)
    if len(runs) == 1 and (runs[0] / "completion.json").is_file() and (runs[0] / "summary.json").is_file():
        return UNVERIFIED
    return INCOMPLETE


def move_aside(results, name, folder="_interrupted", clock=time.time):
    """Move a batch's directory to `<results>/<folder>/<name>-<epoch>`; returns the new path."""
    source = Path(results) / name
    target = Path(results) / folder / f"{name}-{int(clock())}"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError(target)
    source.rename(target)
    return target


def rows(results, name):
    """A batch's per-episode rows (its summary.json), or [] if it has none."""
    runs = run_dirs(Path(results) / name)
    if len(runs) != 1 or not (runs[0] / "summary.json").is_file():
        return []
    return json.loads((runs[0] / "summary.json").read_text())["rows"]


def events(results, name):
    runs = run_dirs(Path(results) / name)
    if len(runs) != 1:
        return []
    with open(runs[0] / "events.jsonl") as handle:
        return [json.loads(line) for line in handle]
