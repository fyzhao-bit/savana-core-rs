import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from savana_bench.agentdojo_native import run


class PinnedBinaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_rebuild_of_source_cannot_change_running_trial_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "test-binary"
            original.write_bytes(b"original synthetic test binary")
            original.chmod(0o700)
            seen = []

            async def execute(*, kernel_test, output, timeout):
                self.assertNotEqual(kernel_test, original)
                self.assertEqual(kernel_test.stat().st_mode & 0o777, 0o500)
                replacement = Path(directory) / "rebuilt"
                replacement.write_bytes(b"different build")
                os.replace(replacement, original)
                self.assertEqual(kernel_test.read_bytes(), b"original synthetic test binary")
                seen.append(kernel_test)
                return {"pinned": True}

            with patch("savana_bench.agentdojo_native._run_pinned", execute):
                self.assertEqual(await run(kernel_test=original, output="unused"), {"pinned": True})
            self.assertFalse(seen[0].exists(), "temporary executable is cleaned up")

    async def test_non_executable_is_rejected_before_any_trial(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "not-executable"
            original.write_bytes(b"synthetic")
            original.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "invalid_test_executable"):
                await run(kernel_test=original, output="unused")
