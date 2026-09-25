from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .errors import RehostError
from .receipt import seal


MASK64 = (1 << 64) - 1


class SideEffect(StrEnum):
    """External effects that an SMC backend may explicitly model."""

    VOLATILE_STATE = "volatile_state"
    PERSISTENT_STORAGE = "persistent_storage"
    MMIO = "mmio"
    OTP = "otp"
    FUSE = "fuse"
    RESET = "reset"


@dataclass(frozen=True, slots=True)
class SmcCall:
    pc: int
    registers: tuple[int, ...]

    def __post_init__(self) -> None:
        if self.pc < 0 or self.pc > MASK64:
            raise ValueError("SMC program counter must be an unsigned 64-bit integer")
        if not 1 <= len(self.registers) <= 8:
            raise ValueError("SMC call must include x0 and at most x0..x7")
        if any(value < 0 or value > MASK64 for value in self.registers):
            raise ValueError("SMC registers must be unsigned 64-bit integers")

    @classmethod
    def from_registers(cls, pc: int, **registers: int) -> SmcCall:
        if "x0" not in registers:
            raise ValueError("SMC call requires x0")
        try:
            indexes = {int(name[1:]) for name in registers if name.startswith("x")}
        except ValueError as exc:
            raise ValueError("SMC registers must be named x0..x7") from exc
        if len(indexes) != len(registers) or not indexes:
            raise ValueError("SMC registers must be named x0..x7")
        highest = max(indexes)
        if highest > 7 or indexes != set(range(highest + 1)):
            raise ValueError("SMC registers must be a contiguous x0..x7 prefix")
        return cls(
            pc=pc,
            registers=tuple(registers[f"x{index}"] for index in range(highest + 1)),
        )

    @property
    def function_id(self) -> int:
        return self.registers[0]

    def as_receipt_value(self) -> dict[str, Any]:
        return {
            "pc": f"0x{self.pc:016x}",
            "registers": {
                f"x{index}": f"0x{value:016x}"
                for index, value in enumerate(self.registers)
            },
        }


@dataclass(frozen=True, slots=True)
class SmcResponse:
    registers: tuple[int, ...]
    effects: frozenset[SideEffect] = frozenset()
    note: str | None = None

    def __post_init__(self) -> None:
        if not 1 <= len(self.registers) <= 4:
            raise ValueError("SMC response must include x0 and at most x0..x3")
        if any(value < 0 or value > MASK64 for value in self.registers):
            raise ValueError("SMC response registers must be unsigned 64-bit integers")

    def as_receipt_value(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "registers": {
                f"x{index}": f"0x{register:016x}"
                for index, register in enumerate(self.registers)
            },
            "effects": sorted(effect.value for effect in self.effects),
        }
        if self.note is not None:
            value["note"] = self.note
        return value


Handler = Callable[[SmcCall], SmcResponse]


@dataclass(frozen=True, slots=True)
class SmcBackend:
    name: str
    mask: int
    value: int
    capabilities: frozenset[SideEffect]
    handler: Handler

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("SMC backend name must be non-empty")
        if not 0 <= self.mask <= MASK64 or not 0 <= self.value <= MASK64:
            raise ValueError("SMC backend mask and value must be unsigned 64-bit integers")
        if self.value & ~self.mask:
            raise ValueError("SMC backend value may not set bits outside its mask")

    def matches(self, function_id: int) -> bool:
        return function_id & self.mask == self.value


class SmcRouter:
    """Typed, auditable SMC routing that rejects every undeclared service.

    Backends declare their possible side effects before execution. A response
    cannot claim an OTP, fuse, reset, or other effect outside that capability
    set. Overlapping backend masks are rejected at dispatch time rather than
    silently relying on registration order.
    """

    def __init__(self, backends: Iterable[SmcBackend]) -> None:
        self._backends = tuple(backends)
        if len({backend.name for backend in self._backends}) != len(self._backends):
            raise ValueError("SMC backend names must be unique")
        self._events: list[dict[str, Any]] = []

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._events)

    def dispatch(self, call: SmcCall) -> SmcResponse:
        matches = [backend for backend in self._backends if backend.matches(call.function_id)]
        if not matches:
            self._events.append(
                {"status": "unmodeled", "call": call.as_receipt_value()}
            )
            raise RehostError(
                "SMC_UNMODELED",
                "SMC function ID has no declared backend",
                {"function_id": f"0x{call.function_id:016x}", "pc": f"0x{call.pc:016x}"},
            )
        if len(matches) != 1:
            names = sorted(backend.name for backend in matches)
            self._events.append(
                {
                    "status": "ambiguous",
                    "call": call.as_receipt_value(),
                    "matching_backends": names,
                }
            )
            raise RehostError(
                "SMC_AMBIGUOUS",
                "SMC function ID matches multiple declared backends",
                {"function_id": f"0x{call.function_id:016x}", "backends": names},
            )

        backend = matches[0]
        response = backend.handler(call)
        undeclared = response.effects - backend.capabilities
        if undeclared:
            raise RehostError(
                "SMC_EFFECT_UNDECLARED",
                "SMC backend returned side effects outside its declared capabilities",
                {
                    "backend": backend.name,
                    "effects": sorted(effect.value for effect in undeclared),
                },
            )
        self._events.append(
            {
                "status": "handled",
                "backend": backend.name,
                "call": call.as_receipt_value(),
                "response": response.as_receipt_value(),
            }
        )
        return response

    def receipt(self, *, target: dict[str, Any], model_id: str) -> dict[str, Any]:
        capabilities = {
            backend.name: sorted(effect.value for effect in backend.capabilities)
            for backend in self._backends
        }
        observed = sorted(
            {
                effect
                for event in self._events
                if event["status"] == "handled"
                for effect in event["response"]["effects"]
            }
        )
        return seal(
            {
                "kind": "typed_smc_service_model",
                "tool": {"name": "verirehost", "version": "0.1.0"},
                "target": target,
                "claim_grade": "synthetic_model",
                "status": "complete",
                "model_id": model_id,
                "backends": capabilities,
                "events": list(self._events),
                "observed_side_effects": observed,
                "claims": [
                    {
                        "id": "typed-smc-routing",
                        "statement": "Every handled SMC matched exactly one declared backend and reported only predeclared modeled side effects.",
                        "grade": "synthetic_model",
                    }
                ],
                "model_boundary": {
                    "executed": ["public SMC router and caller-supplied backend functions"],
                    "modeled": ["SMC register exchange", "declared service side effects"],
                    "not_claimed": [
                        "vendor secure-monitor behavior",
                        "physical OTP or fuse state",
                        "MMIO, persistence, or reset not declared by a backend",
                        "whole-firmware or physical-device behavior",
                    ],
                },
                "adaptations": [
                    "unknown services fail closed",
                    "overlapping service matches fail closed",
                    "backend side effects are capability checked",
                ],
            }
        )
