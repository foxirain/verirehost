from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from verirehost.errors import RehostError
from verirehost.exact_slice import run_exact_slice
from verirehost.receipt import verify


try:
    import unicorn  # noqa: F401
except ImportError:
    HAS_UNICORN = False
else:
    HAS_UNICORN = True


@unittest.skipUnless(HAS_UNICORN, "optional exact engine is not installed")
class ExactSliceTests(unittest.TestCase):
    def test_straight_slice_reaches_stop_and_seals_receipt(self) -> None:
        # mov x0, #42; nop
        code = bytes.fromhex("400580d21f2003d5")
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "synthetic-aarch64.bin"
            artifact.write_bytes(code)
            receipt = run_exact_slice(
                artifact,
                target={"id": "synthetic-control", "architecture": "aarch64"},
                image_base=0x100000,
                entry=0x100000,
                stop_exclusive=0x100008,
                stack_base=0x200000,
                stack_size=0x1000,
                initial_registers={"x0": 0},
                max_instructions=8,
            )

        verify(receipt)
        self.assertEqual(receipt["status"], "stop_reached")
        self.assertEqual(receipt["execution"]["final_registers"]["x0"], 42)
        self.assertEqual(receipt["budget"]["executed_instructions"], 2)
        self.assertNotIn("synthetic-aarch64.bin", str(receipt))

    def test_branch_escape_fails_closed(self) -> None:
        # b +12; nop; nop; nop -- stop excludes the branch target.
        code = bytes.fromhex("030000141f2003d51f2003d51f2003d5")
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "escape.bin"
            artifact.write_bytes(code)
            with self.assertRaises(RehostError) as raised:
                run_exact_slice(
                    artifact,
                    target={"id": "synthetic-escape", "architecture": "aarch64"},
                    image_base=0x300000,
                    entry=0x300000,
                    stop_exclusive=0x300008,
                    stack_base=0x400000,
                    stack_size=0x1000,
                    max_instructions=8,
                )
        self.assertEqual(raised.exception.code, "EXACT_SLICE_ESCAPE")


if __name__ == "__main__":
    unittest.main()
