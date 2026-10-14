import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from savana_bench.publication_audit import PrivateEpisodeAudit, _canonical


def events():
    scope = {k: "1" * 64 for k in ("task_id", "run_id", "root_digest", "destination_digest")}
    commit = {**scope, **{k: "2" * 64 for k in ("release_id", "payload_digest", "approval_digest",
        "receipt_digest", "audit_digest", "commit_digest")}}
    return [dict(kind="private_wait_started", **scope),
        dict(kind="private_publication_committed", **commit),
        dict(kind="private_payload_verified", commit_digest="2" * 64, payload_digest="2" * 64, payload_bytes=12),
        dict(kind="private_episode_observed", status="published", stage="complete", utility=None, attacker_success=None)]


class PublicationAuditTests(unittest.TestCase):
    def test_public_directory_and_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            public = Path(directory) / "public"
            public.mkdir(mode=0o755)
            with self.assertRaises(ValueError):
                PrivateEpisodeAudit(public / "log")
            link = Path(directory) / "link"
            link.symlink_to(public, target_is_directory=True)
            with self.assertRaises(OSError):
                PrivateEpisodeAudit(link / "log")

    def test_exclusive_private_fsynced_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "publication.jsonl"
            with PrivateEpisodeAudit(path) as audit, patch("os.fsync", wraps=os.fsync) as fsync:
                for event in events():
                    audit(event)
                self.assertEqual(fsync.call_count, 4)
                final = audit.final_digest
                with self.assertRaises(ValueError):
                    audit(events()[-1])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            previous = "0" * 64
            for sequence, row in enumerate(map(json.loads, path.read_bytes().splitlines())):
                digest = row.pop("sha256")
                self.assertEqual(digest, hashlib.sha256(_canonical(row)).hexdigest())
                self.assertEqual((row["sequence"], row["previous"]), (sequence, previous))
                previous = digest
            self.assertEqual(previous, final)
            with self.assertRaises(FileExistsError):
                PrivateEpisodeAudit(path)

    def test_no_scope_rebind_plaintext_or_premature_success(self):
        with tempfile.TemporaryDirectory() as directory, PrivateEpisodeAudit(Path(directory) / "events") as audit:
            values = events()
            audit(values[0])
            for bad in [values[-1], {**values[1], "task_id": "3" * 64},
                        {**values[1], "raw_result": "private"}, {**values[1], "receipt_digest": "0" * 64}]:
                with self.assertRaises(ValueError):
                    audit(bad)
            audit(dict(kind="private_episode_observed", status="unknown", stage="wait_publication", utility=None, attacker_success=None))

    def test_uncertain_write_is_not_retried(self):
        with tempfile.TemporaryDirectory() as directory, PrivateEpisodeAudit(Path(directory) / "events") as audit:
            with patch("os.fsync", side_effect=OSError("synthetic disk failure")):
                with self.assertRaises(OSError):
                    audit(events()[0])
            with self.assertRaises(ValueError):
                audit(events()[0])
            with self.assertRaises(ValueError):
                _ = audit.final_digest

    def test_partial_writes_and_payload_binding(self):
        with tempfile.TemporaryDirectory() as directory, PrivateEpisodeAudit(Path(directory) / "events") as audit:
            original = os.write
            with patch("os.write", side_effect=lambda fd, data: original(fd, data[:13])):
                audit(events()[0])
            audit(events()[1])
            for bad in [{**events()[2], "payload_bytes": True}, {**events()[2], "payload_bytes": 32769},
                        {**events()[2], "payload_digest": "3" * 64}]:
                with self.assertRaises(ValueError):
                    audit(bad)
            audit(events()[2])
            with self.assertRaises(ValueError):
                audit({**events()[3], "utility": True})
            audit(events()[3])


if __name__ == "__main__":
    unittest.main()
