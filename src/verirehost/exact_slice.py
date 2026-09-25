from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import Any

from . import __version__
from .errors import RehostError
from .receipt import seal


PAGE_SIZE = 0x1000
MAX_IMAGE_SIZE = 128 * 1024 * 1024
MAX_INSTRUCTIONS = 1_000_000


def _align_up(value: int, alignment: int = PAGE_SIZE) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _load_engine() -> tuple[Any, Any, str]:
    try:
        import unicorn
        from unicorn import Uc
        from unicorn import arm64_const
    except ImportError as exc:
        raise RehostError(
            "EXACT_ENGINE_MISSING",
            "bounded exact-slice execution requires the optional 'exact' dependency",
            {"install": "python -m pip install -e '.[exact]'"},
        ) from exc
    return unicorn, (Uc, arm64_const), unicorn.__version__


def _register_id(registers: Any, name: str) -> int:
    normalized = name.strip().lower()
    if normalized == "sp":
        return registers.UC_ARM64_REG_SP
    if normalized == "pc":
        return registers.UC_ARM64_REG_PC
    if normalized.startswith("x") and normalized[1:].isdigit():
        number = int(normalized[1:])
        if 0 <= number <= 30:
            return getattr(registers, f"UC_ARM64_REG_X{number}")
    raise RehostError("EXACT_REGISTER", "unsupported AArch64 register", {"register": name})


def run_exact_slice(
    artifact: Path,
    *,
    target: dict[str, Any],
    image_base: int,
    entry: int,
    stop_exclusive: int,
    stack_base: int,
    stack_size: int,
    initial_registers: dict[str, int] | None = None,
    max_instructions: int = 256,
) -> dict[str, Any]:
    """Execute one straight bounded AArch64 slice and seal a path-free receipt.

    The runner has no service hooks, MMIO model, storage backend, or transport.
    Any control-flow escape from the declared slice fails closed.
    """

    if image_base < 0 or image_base % PAGE_SIZE:
        raise RehostError("EXACT_LAYOUT", "image_base must be page aligned")
    if stack_base < 0 or stack_base % PAGE_SIZE:
        raise RehostError("EXACT_LAYOUT", "stack_base must be page aligned")
    if stack_size <= 0 or stack_size % PAGE_SIZE:
        raise RehostError("EXACT_LAYOUT", "stack_size must be a positive page multiple")
    if not 0 < max_instructions <= MAX_INSTRUCTIONS:
        raise RehostError("EXACT_BUDGET", "max_instructions is outside the supported range")

    data = artifact.read_bytes()
    if not data or len(data) > MAX_IMAGE_SIZE:
        raise RehostError(
            "EXACT_ARTIFACT_SIZE",
            "artifact must be non-empty and no larger than the public runner limit",
            {"maximum": MAX_IMAGE_SIZE, "observed": len(data)},
        )
    image_size = _align_up(len(data))
    image_stop = image_base + len(data)
    if not image_base <= entry < stop_exclusive <= image_stop:
        raise RehostError(
            "EXACT_RANGE",
            "entry and stop_exclusive must form a non-empty range inside the artifact",
        )
    if entry % 4 or stop_exclusive % 4:
        raise RehostError("EXACT_RANGE", "AArch64 slice boundaries must be 4-byte aligned")
    if not (
        stack_base + stack_size <= image_base
        or image_base + image_size <= stack_base
    ):
        raise RehostError("EXACT_LAYOUT", "stack and image mappings overlap")

    unicorn, engine_types, engine_version = _load_engine()
    Uc, registers = engine_types
    machine = Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM)
    machine.mem_map(
        image_base,
        image_size,
        unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE | unicorn.UC_PROT_EXEC,
    )
    machine.mem_write(image_base, data)
    machine.mem_protect(
        image_base, image_size, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC
    )
    machine.mem_map(
        stack_base,
        stack_size,
        unicorn.UC_PROT_READ | unicorn.UC_PROT_WRITE,
    )

    stack_pointer = stack_base + stack_size - 16
    machine.reg_write(registers.UC_ARM64_REG_SP, stack_pointer)
    machine.reg_write(registers.UC_ARM64_REG_X29, stack_pointer)
    declared_registers = initial_registers or {}
    for name, value in declared_registers.items():
        if not isinstance(value, int) or value < 0 or value > 0xFFFFFFFFFFFFFFFF:
            raise RehostError(
                "EXACT_REGISTER",
                "initial register values must be unsigned 64-bit integers",
                {"register": name},
            )
        machine.reg_write(_register_id(registers, name), value)

    executed_addresses: list[int] = []
    executed_bytes = hashlib.sha256()

    def trace(emulator: Any, address: int, size: int, _user_data: Any) -> None:
        if not entry <= address < stop_exclusive:
            raise RehostError(
                "EXACT_SLICE_ESCAPE",
                "execution left the declared code range",
                {"address": f"0x{address:x}"},
            )
        executed_addresses.append(address)
        executed_bytes.update(bytes(emulator.mem_read(address, size)))

    machine.hook_add(unicorn.UC_HOOK_CODE, trace)
    try:
        machine.emu_start(
            entry,
            stop_exclusive,
            timeout=100_000,
            count=max_instructions,
        )
    except RehostError:
        raise
    except unicorn.UcError as exc:
        raise RehostError(
            "EXACT_ENGINE",
            "AArch64 slice execution failed",
            {"engine_error": str(exc)},
        ) from exc

    final_pc = machine.reg_read(registers.UC_ARM64_REG_PC)
    if final_pc != stop_exclusive:
        raise RehostError(
            "EXACT_STOP",
            "slice did not reach its declared exclusive stop",
            {
                "pc": f"0x{final_pc:x}",
                "instruction_count": len(executed_addresses),
            },
        )

    address_digest = hashlib.sha256()
    for address in executed_addresses:
        address_digest.update(struct.pack("<Q", address))

    observed_registers = {
        name.lower(): machine.reg_read(_register_id(registers, name))
        for name in sorted(declared_registers)
    }
    observed_registers["pc"] = final_pc
    observed_registers["sp"] = machine.reg_read(registers.UC_ARM64_REG_SP)

    return seal(
        {
            "kind": "bounded_exact_aarch64_slice",
            "tool": {"name": "verirehost", "version": __version__},
            "target": target,
            "claim_grade": "exact_binary_slice",
            "status": "stop_reached",
            "artifact": {
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            },
            "layout": {
                "architecture": "aarch64",
                "image_base": image_base,
                "entry": entry,
                "stop_exclusive": stop_exclusive,
                "stack_base": stack_base,
                "stack_size": stack_size,
            },
            "budget": {
                "maximum_instructions": max_instructions,
                "executed_instructions": len(executed_addresses),
                "timeout_microseconds": 100_000,
            },
            "execution": {
                "engine": {"name": "unicorn", "version": engine_version},
                "executed_address_sha256": address_digest.hexdigest(),
                "executed_bytes_sha256": executed_bytes.hexdigest(),
                "final_registers": observed_registers,
            },
            "claims": [
                {
                    "id": "bounded-exact-slice-stop-reached",
                    "statement": "The hash-bound AArch64 slice reached its declared exclusive stop without leaving the permitted code range.",
                    "grade": "exact_binary_slice",
                }
            ],
            "model_boundary": {
                "executed": ["artifact bytes inside the declared code range"],
                "modeled": ["initial registers", "bounded stack memory"],
                "not_claimed": [
                    "whole-firmware behavior",
                    "device peripherals or MMIO",
                    "physical timing",
                    "storage, transport, or persistence",
                    "security impact",
                ],
            },
            "adaptations": [
                "no service hooks are available in the public generic runner",
                "the local artifact path is excluded from the receipt",
                "unknown code and unmapped memory fail closed",
            ],
        }
    )
