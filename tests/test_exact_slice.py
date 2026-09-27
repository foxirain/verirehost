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
        self.assertEqual(receipt["initial_state"]["declared_registers"], {"x0": 0})
        self.assertEqual(receipt["initial_state"]["effective_registers"]["x0"], 0)
        self.assertEqual(receipt["initial_state"]["effective_registers"]["pc"], 0x100000)
        self.assertEqual(receipt["initial_state"]["effective_registers"]["sp"], 0x200FF0)
        self.assertEqual(receipt["initial_state"]["effective_registers"]["x29"], 0x200FF0)
        self.assertEqual(receipt["initial_state"]["unspecified_x0_x30"], 0)
        self.assertEqual(receipt["initial_state"]["nzcv"], 0)
        self.assertEqual(receipt["execution"]["final_registers"]["x0"], 42)
        self.assertEqual(receipt["budget"]["executed_instructions"], 2)
        self.assertNotIn("synthetic-aarch64.bin", str(receipt))

    def test_initial_registers_are_bound_when_execution_outcome_matches(self) -> None:
        # mov x0, #42; nop -- both initial x0 values are overwritten.
        code = bytes.fromhex("400580d21f2003d5")
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "synthetic-aarch64.bin"
            artifact.write_bytes(code)
            arguments = {
                "target": {"id": "synthetic-input-binding", "architecture": "aarch64"},
                "image_base": 0x100000,
                "entry": 0x100000,
                "stop_exclusive": 0x100008,
                "stack_base": 0x200000,
                "stack_size": 0x1000,
                "max_instructions": 8,
            }
            first = run_exact_slice(artifact, initial_registers={"x0": 0}, **arguments)
            second = run_exact_slice(artifact, initial_registers={" X0 ": 99}, **arguments)

        verify(first)
        verify(second)
        self.assertEqual(first["execution"], second["execution"])
        self.assertEqual(first["execution"]["final_registers"]["x0"], 42)
        self.assertEqual(first["initial_state"]["declared_registers"], {"x0": 0})
        self.assertEqual(second["initial_state"]["declared_registers"], {"x0": 99})
        self.assertNotEqual(first["content_id"], second["content_id"])

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


class ExactSliceInputValidationTests(unittest.TestCase):
    def arguments(self) -> dict[str, object]:
        return {
            "target": {"id": "synthetic-validation", "architecture": "aarch64"},
            "image_base": 0x100000,
            "entry": 0x100000,
            "stop_exclusive": 0x100004,
            "stack_base": 0x200000,
            "stack_size": 0x1000,
            "max_instructions": 1,
        }

    def test_register_alias_duplicates_fail_before_engine_or_artifact_access(self) -> None:
        with self.assertRaises(RehostError) as raised:
            run_exact_slice(
                Path("not-accessed.bin"),
                initial_registers={"X0": 1, " x0 ": 2},
                **self.arguments(),
            )
        self.assertEqual(raised.exception.code, "EXACT_REGISTER")
        self.assertIn("more than once", str(raised.exception))

    def test_pc_cannot_conflict_with_the_declared_entry(self) -> None:
        with self.assertRaises(RehostError) as raised:
            run_exact_slice(
                Path("not-accessed.bin"),
                initial_registers={"pc": 0x100000},
                **self.arguments(),
            )
        self.assertEqual(raised.exception.code, "EXACT_REGISTER")
        self.assertIn("entry address", str(raised.exception))

    def test_boolean_register_values_are_rejected(self) -> None:
        with self.assertRaises(RehostError) as raised:
            run_exact_slice(
                Path("not-accessed.bin"),
                initial_registers={"x0": True},
                **self.arguments(),
            )
        self.assertEqual(raised.exception.code, "EXACT_REGISTER")


if __name__ == "__main__":
    unittest.main()
