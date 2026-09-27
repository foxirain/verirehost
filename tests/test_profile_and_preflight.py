from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from verirehost.kernel_preflight import inspect
from verirehost.profile import load


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ProfileTests(unittest.TestCase):
    def test_public_profiles_validate(self) -> None:
        synthetic, _ = load(PROJECT_ROOT / "profiles" / "synthetic-slice.example.json")
        self.assertEqual(synthetic["claim_grade"], "synthetic_model")
        self.assertEqual(synthetic["target"]["architecture"], "aarch64")

        demo, _ = load(PROJECT_ROOT / "profiles" / "public-exact-slice-demo.json")
        self.assertEqual(demo["claim_grade"], "synthetic_model")
        self.assertEqual(demo["artifacts"]["firmware"]["size"], 8)
        self.assertEqual(demo["experiment"]["initial_registers"], {"x0": 41})


class KernelPreflightTests(unittest.TestCase):
    def test_usb_lane_does_not_require_virtio_blk(self) -> None:
        receipt = inspect(PROJECT_ROOT / "fixtures" / "synthetic" / "qemu-usb-ready.config")
        self.assertEqual(receipt["status"], "compatible")
        self.assertFalse(receipt["observations"]["virtio_blk_enabled"])
        self.assertFalse(receipt["observations"]["virtio_blk_required"])

    def test_missing_xhci_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config"
            config.write_text("CONFIG_ARM64=y\n", encoding="utf-8")
            receipt = inspect(config)
        self.assertEqual(receipt["status"], "incompatible")
        failed = {item["capability"] for item in receipt["checks"] if not item["passed"]}
        self.assertIn("xhci", failed)
        self.assertIn("usb_mass_storage", failed)


if __name__ == "__main__":
    unittest.main()
