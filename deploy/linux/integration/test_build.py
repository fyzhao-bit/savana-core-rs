import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

import pytest

spec = importlib.util.spec_from_file_location("integration_build", Path(__file__).with_name("build.py"))
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)


def test_clean_rebuilds_all_workspace_members_not_third_party_dependencies():
    metadata = {"workspace_members": ["id-protocol", "id-kernel"], "packages": [
        {"id": "id-protocol", "name": "savana-kernel-protocol"},
        {"id": "id-kernel", "name": "savana-kerneld"},
        {"id": "external", "name": "serde"}]}
    with patch.object(build.subprocess, "check_output", return_value=json.dumps(metadata)), \
         patch.object(build.subprocess, "run") as run:
        build.clean_workspace(Path("/workspace"))
    run.assert_called_once_with(["cargo", "clean", "--profile", "integration",
                                 "--package", "savana-kernel-protocol",
                                 "--package", "savana-kerneld"], cwd=Path("/workspace"), check=True)


def test_incomplete_metadata_cannot_skip_clean():
    with patch.object(build.subprocess, "check_output", return_value='{"workspace_members":["missing"],"packages":[]}'), \
         patch.object(build.subprocess, "run") as run, pytest.raises(RuntimeError):
        build.clean_workspace(Path("/workspace"))
    run.assert_not_called()


def test_snapshot_detects_content_changes_even_if_mtime_is_older(tmp_path):
    (tmp_path / "Cargo.toml").write_text("[workspace]")
    (tmp_path / "Cargo.lock").write_text("version = 3")
    source = tmp_path / "crates/example/src"
    source.mkdir(parents=True)
    asset = source / "browser_assets.rs"
    asset.write_text("old")
    before = build.source_snapshot(tmp_path)
    asset.write_text("new")
    import os
    os.utime(asset, (1, 1))
    assert before != build.source_snapshot(tmp_path)
