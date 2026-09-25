from __future__ import annotations

import struct
from dataclasses import dataclass


def sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def decode_adrp(word: int, pc: int) -> tuple[int, int] | None:
    if word & 0x9F000000 != 0x90000000:
        return None
    immlo = (word >> 29) & 0x3
    immhi = (word >> 5) & 0x7FFFF
    delta = sign_extend((immhi << 2) | immlo, 21) << 12
    return word & 0x1F, (pc & ~0xFFF) + delta


def decode_add_immediate(word: int) -> tuple[int, int, int] | None:
    if word & 0x7F800000 != 0x11000000:
        return None
    destination = word & 0x1F
    source = (word >> 5) & 0x1F
    immediate = (word >> 10) & 0xFFF
    if word & (1 << 22):
        immediate <<= 12
    return destination, source, immediate


def decode_direct_branch(word: int, pc: int) -> tuple[str, int] | None:
    opcode = word & 0xFC000000
    if opcode not in (0x14000000, 0x94000000):
        return None
    delta = sign_extend(word & 0x03FFFFFF, 26) << 2
    return ("bl" if opcode == 0x94000000 else "b"), pc + delta


@dataclass(frozen=True, slots=True)
class Reference:
    kind: str
    instruction_address: int
    companion_address: int | None = None

    def as_receipt_value(self) -> dict[str, str]:
        value = {"kind": self.kind, "instruction_address": f"0x{self.instruction_address:08x}"}
        if self.companion_address is not None:
            value["companion_address"] = f"0x{self.companion_address:08x}"
        return value


def find_references(data: bytes, base: int, target: int, *, window: int = 8) -> list[Reference]:
    word_count = len(data) // 4
    words = struct.unpack_from(f"<{word_count}I", data)
    references: list[Reference] = []
    for index, word in enumerate(words):
        pc = base + index * 4
        branch = decode_direct_branch(word, pc)
        if branch is not None and branch[1] == target:
            references.append(Reference(branch[0], pc))

        page = decode_adrp(word, pc)
        if page is None:
            continue
        page_register, page_address = page
        for lookahead in range(1, window + 1):
            next_index = index + lookahead
            if next_index >= word_count:
                break
            add = decode_add_immediate(words[next_index])
            if add is None:
                continue
            _, source_register, immediate = add
            if source_register == page_register and page_address + immediate == target:
                references.append(Reference("adrp_add", pc, base + next_index * 4))
    return references
