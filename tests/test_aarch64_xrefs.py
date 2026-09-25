from __future__ import annotations

import struct
import unittest

from verirehost.aarch64_xrefs import decode_direct_branch, find_references


def encode_bl(pc: int, target: int) -> int:
    return 0x94000000 | (((target - pc) >> 2) & 0x03FFFFFF)


def encode_adrp(pc: int, target: int, register: int) -> int:
    delta = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    encoded = delta & 0x1FFFFF
    immlo = encoded & 0x3
    immhi = encoded >> 2
    return 0x90000000 | (immlo << 29) | (immhi << 5) | register


def encode_add(register: int, immediate: int) -> int:
    return 0x91000000 | ((immediate & 0xFFF) << 10) | (register << 5) | register


class Aarch64ReferenceTests(unittest.TestCase):
    def test_finds_direct_call_and_adrp_add_reference(self) -> None:
        base = 0x02000000
        branch_target = base + 0x100
        string_target = base + 0x2345
        words = [
            encode_bl(base, branch_target),
            encode_adrp(base + 4, string_target, 9),
            encode_add(9, string_target & 0xFFF),
        ]
        data = struct.pack("<3I", *words)

        branch = find_references(data, base, branch_target)
        string = find_references(data, base, string_target)

        self.assertEqual([(item.kind, item.instruction_address) for item in branch], [("bl", base)])
        self.assertEqual(len(string), 1)
        self.assertEqual(string[0].instruction_address, base + 4)
        self.assertEqual(string[0].companion_address, base + 8)

    def test_direct_branch_sign_extension_handles_backward_calls(self) -> None:
        pc = 0x02000100
        target = 0x02000020
        self.assertEqual(decode_direct_branch(encode_bl(pc, target), pc), ("bl", target))


if __name__ == "__main__":
    unittest.main()
