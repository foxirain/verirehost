from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from verirehost.artifact_binding import bind
from verirehost.canonical import canonical_bytes, sha256_bytes


class ArtifactBindingTests(unittest.TestCase):
    def test_match_and_mismatch_receipts_do_not_leak_path(self) -> None:
        profile = {
            "id": "binding-test",
            "target": {"family": "synthetic"},
            "artifacts": {
                "sboot": {"sha256": sha256_bytes(b"expected"), "size": 8, "redistributable": False}
            },
        }
        profile_bytes = canonical_bytes(profile)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private-sboot.bin"
            path.write_bytes(b"expected")
            matched = bind(profile, profile_bytes, "sboot", path)
            path.write_bytes(b"changed")
            mismatch = bind(profile, profile_bytes, "sboot", path)

        self.assertEqual(matched["status"], "matched")
        self.assertEqual(mismatch["status"], "mismatch")
        self.assertNotIn("private-sboot.bin", str(matched))
        self.assertEqual(len(matched["claims"]), 1)
        self.assertEqual(mismatch["claims"], [])


if __name__ == "__main__":
    unittest.main()
