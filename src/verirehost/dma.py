from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from . import __version__
from .errors import RehostError
from .receipt import seal


MAX_TRANSFER_LENGTH = 1 << 40
MAX_WINDOW_LENGTH = 16 << 20


class VisibilityPolicy(StrEnum):
    """When device-written bytes become visible through the CPU view."""

    PACKET = "packet"
    COMPLETION = "completion"
    EXPLICIT_SYNC = "explicit_sync"


class TransferState(StrEnum):
    ACTIVE = "active"
    COMPLETED = "completed"
    CANCELED = "canceled"


class ResetDisposition(StrEnum):
    """How reset treats an active DMA request."""

    FAIL_IF_ACTIVE = "fail_if_active"
    PRESERVE_CPU_VISIBLE = "preserve_cpu_visible"
    COMMIT_DEVICE_VISIBLE = "commit_device_visible"
    DISCARD_UNCOMMITTED = "discard_uncommitted"


@dataclass(frozen=True, slots=True)
class DmaDescriptor:
    offset: int
    length: int
    hardware_owned: bool = True
    chained: bool = False
    interrupt_on_completion: bool = False
    last: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.offset, bool) or not isinstance(self.offset, int) or self.offset < 0:
            raise ValueError("descriptor offset must be a non-negative integer")
        if isinstance(self.length, bool) or not isinstance(self.length, int) or self.length <= 0:
            raise ValueError("descriptor length must be a positive integer")

    def as_dict(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "length": self.length,
            "hardware_owned": self.hardware_owned,
            "chained": self.chained,
            "interrupt_on_completion": self.interrupt_on_completion,
            "last": self.last,
        }


@dataclass(frozen=True, slots=True)
class DmaDescriptorChain:
    descriptors: tuple[DmaDescriptor, ...]

    def __post_init__(self) -> None:
        if not self.descriptors:
            raise ValueError("DMA descriptor chain must not be empty")
        expected = 0
        for index, descriptor in enumerate(self.descriptors):
            if descriptor.offset != expected:
                raise ValueError("DMA descriptors must form a contiguous zero-based chain")
            is_last = index == len(self.descriptors) - 1
            if descriptor.last != is_last:
                raise ValueError("only the final DMA descriptor may be marked last")
            if descriptor.chained == is_last:
                raise ValueError("non-final descriptors must be chained and final must not")
            expected += descriptor.length

    @property
    def capacity(self) -> int:
        return sum(item.length for item in self.descriptors)

    def validate_request(self, declared_length: int) -> None:
        if self.capacity < declared_length:
            raise RehostError(
                "DMA_CHAIN_SHORT",
                "descriptor chain is shorter than the declared transfer",
                {"capacity": self.capacity, "declared_length": declared_length},
            )
        if not all(item.hardware_owned for item in self.descriptors):
            raise RehostError(
                "DMA_CHAIN_OWNERSHIP",
                "all descriptors must be hardware-owned at submission",
            )

    def first_descriptor_contains(self, length: int) -> bool:
        return 0 <= length <= self.descriptors[0].length

    def as_list(self) -> list[dict[str, Any]]:
        return [item.as_dict() for item in self.descriptors]


def _sha256(value: bytes | bytearray) -> str:
    return hashlib.sha256(value).hexdigest()


class DmaTransfer:
    """Sparse-window model for packet arrival, DMA, coherence, and completion.

    ``declared_length`` models the whole hardware request while ``initial_window``
    bounds the CPU-observable bytes kept by the model. This permits large active
    transfers to be studied without allocating their entire backing arena.
    Device and CPU views are separate so that packet, completion, and explicit
    synchronization policies have distinct, testable behavior.
    """

    def __init__(
        self,
        *,
        transfer_id: str,
        declared_length: int,
        maximum_packet_size: int,
        initial_window: bytes,
        visibility: VisibilityPolicy,
        descriptors: DmaDescriptorChain,
    ) -> None:
        if not isinstance(transfer_id, str) or not transfer_id.strip():
            raise ValueError("transfer_id must be non-empty")
        if (
            isinstance(declared_length, bool)
            or not isinstance(declared_length, int)
            or not 1 <= declared_length <= MAX_TRANSFER_LENGTH
        ):
            raise ValueError("declared_length is outside the supported range")
        if (
            isinstance(maximum_packet_size, bool)
            or not isinstance(maximum_packet_size, int)
            or maximum_packet_size <= 0
            or maximum_packet_size & (maximum_packet_size - 1)
        ):
            raise ValueError("maximum_packet_size must be a positive power of two")
        if not isinstance(initial_window, bytes) or not initial_window:
            raise ValueError("initial_window must be non-empty bytes")
        if len(initial_window) > min(declared_length, MAX_WINDOW_LENGTH):
            raise ValueError("initial_window exceeds the modeled transfer window")
        if not isinstance(visibility, VisibilityPolicy):
            raise ValueError("visibility must be a VisibilityPolicy")
        descriptors.validate_request(declared_length)

        self.transfer_id = transfer_id
        self.declared_length = declared_length
        self.maximum_packet_size = maximum_packet_size
        self.visibility = visibility
        self.descriptors = descriptors
        self._initial = initial_window
        self._device = bytearray(initial_window)
        self._cpu = bytearray(initial_window)
        self._received = 0
        self._state = TransferState.ACTIVE
        self._events: list[dict[str, Any]] = []

    @property
    def state(self) -> TransferState:
        return self._state

    @property
    def received_length(self) -> int:
        return self._received

    @property
    def active(self) -> bool:
        return self._state == TransferState.ACTIVE

    @property
    def cpu_window(self) -> bytes:
        return bytes(self._cpu)

    @property
    def device_window(self) -> bytes:
        return bytes(self._device)

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._events)

    def _write_window(self, destination: bytearray, offset: int, payload: bytes) -> None:
        start = min(offset, len(destination))
        end = min(offset + len(payload), len(destination))
        if start < end:
            destination[start:end] = payload[start - offset : end - offset]

    @staticmethod
    def _validate_tick(tick: int) -> None:
        if isinstance(tick, bool) or not isinstance(tick, int) or tick < 0:
            raise RehostError("DMA_TICK", "DMA event tick must be a non-negative integer")

    def submit_packet(self, payload: bytes, *, tick: int) -> None:
        self._validate_tick(tick)
        if self._state != TransferState.ACTIVE:
            raise RehostError("DMA_INACTIVE", "cannot submit a packet to an inactive transfer")
        if not isinstance(payload, bytes):
            raise RehostError("DMA_PACKET", "DMA packet payload must be bytes")
        if len(payload) > self.maximum_packet_size:
            raise RehostError(
                "DMA_PACKET",
                "DMA packet exceeds the declared maximum packet size",
                {"maximum_packet_size": self.maximum_packet_size, "observed": len(payload)},
            )
        if self._received + len(payload) > self.declared_length:
            raise RehostError("DMA_OVERFLOW", "DMA packet exceeds the declared transfer length")

        offset = self._received
        self._write_window(self._device, offset, payload)
        if self.visibility == VisibilityPolicy.PACKET:
            self._write_window(self._cpu, offset, payload)
        self._received += len(payload)
        completion_reason: str | None = None
        if not payload:
            completion_reason = "zero_length_packet"
        elif len(payload) < self.maximum_packet_size:
            completion_reason = "short_packet"
        elif self._received == self.declared_length:
            completion_reason = "declared_length"

        self._events.append(
            {
                "tick": tick,
                "kind": "packet",
                "offset": offset,
                "length": len(payload),
                "payload_sha256": _sha256(payload),
                "completion_reason": completion_reason,
                "cpu_window_sha256": _sha256(self._cpu),
                "device_window_sha256": _sha256(self._device),
            }
        )
        if completion_reason is not None:
            self._complete(tick=tick, reason=completion_reason)

    def _complete(self, *, tick: int, reason: str) -> None:
        if self.visibility == VisibilityPolicy.COMPLETION:
            self._cpu[:] = self._device
        self._state = TransferState.COMPLETED
        self._events.append(
            {
                "tick": tick,
                "kind": "completion",
                "reason": reason,
                "interrupt": any(
                    item.interrupt_on_completion for item in self.descriptors.descriptors
                ),
                "cpu_window_sha256": _sha256(self._cpu),
            }
        )

    def sync_for_cpu(self, *, tick: int) -> None:
        self._validate_tick(tick)
        if self._state == TransferState.CANCELED:
            raise RehostError("DMA_INACTIVE", "cannot synchronize a canceled transfer")
        if self.visibility != VisibilityPolicy.EXPLICIT_SYNC:
            raise RehostError(
                "DMA_SYNC_POLICY",
                "explicit CPU synchronization is undeclared for this visibility policy",
                {"visibility": self.visibility.value},
            )
        self._cpu[:] = self._device
        self._events.append(
            {
                "tick": tick,
                "kind": "sync_for_cpu",
                "cpu_window_sha256": _sha256(self._cpu),
            }
        )

    def observe_cpu(self, *, tick: int, length: int | None = None) -> bytes:
        self._validate_tick(tick)
        if length is not None and (
            isinstance(length, bool) or not isinstance(length, int) or length < 0
        ):
            raise RehostError("DMA_OBSERVE", "observation length must be non-negative")
        observed = bytes(self._cpu if length is None else self._cpu[:length])
        self._events.append(
            {
                "tick": tick,
                "kind": "cpu_observation",
                "length": len(observed),
                "sha256": _sha256(observed),
                "transfer_active": self.active,
            }
        )
        return observed

    def reset(self, *, tick: int, disposition: ResetDisposition) -> None:
        self._validate_tick(tick)
        if not isinstance(disposition, ResetDisposition):
            raise ValueError("disposition must be a ResetDisposition")
        if self._state != TransferState.ACTIVE:
            self._events.append(
                {
                    "tick": tick,
                    "kind": "reset_after_terminal_transfer",
                    "prior_state": self._state.value,
                    "disposition": disposition.value,
                }
            )
            return
        if disposition == ResetDisposition.FAIL_IF_ACTIVE:
            raise RehostError(
                "DMA_RESET_ACTIVE",
                "reset policy rejects an active DMA transfer",
                {"transfer_id": self.transfer_id, "received_length": self._received},
            )
        if disposition == ResetDisposition.COMMIT_DEVICE_VISIBLE:
            self._cpu[:] = self._device
        elif disposition == ResetDisposition.DISCARD_UNCOMMITTED:
            self._device[:] = self._cpu
        self._state = TransferState.CANCELED
        self._events.append(
            {
                "tick": tick,
                "kind": "reset",
                "disposition": disposition.value,
                "received_length": self._received,
                "cpu_window_sha256": _sha256(self._cpu),
                "device_window_sha256": _sha256(self._device),
            }
        )

    def receipt(self, *, model_id: str) -> dict[str, Any]:
        return seal(
            {
                "kind": "temporal_dma_visibility_model",
                "tool": {"name": "verirehost", "version": __version__},
                "target": {"id": model_id, "kind": "synthetic_dma_contract"},
                "claim_grade": "synthetic_model",
                "status": "complete",
                "transfer": {
                    "id": self.transfer_id,
                    "declared_length": self.declared_length,
                    "maximum_packet_size": self.maximum_packet_size,
                    "modeled_window_length": len(self._cpu),
                    "visibility_policy": self.visibility.value,
                    "descriptors": self.descriptors.as_list(),
                },
                "result": {
                    "state": self._state.value,
                    "received_length": self._received,
                    "transfer_active": self.active,
                    "initial_window_sha256": _sha256(self._initial),
                    "device_window_sha256": _sha256(self._device),
                    "cpu_window_sha256": _sha256(self._cpu),
                },
                "events": list(self._events),
                "claims": [
                    {
                        "id": "declared-dma-policy-observation",
                        "statement": (
                            "The recorded CPU-visible bytes follow the declared packet, "
                            "completion, or explicit-sync visibility policy."
                        ),
                        "grade": "synthetic_model",
                    }
                ],
                "model_boundary": {
                    "executed": ["VeriRehost sparse-window DMA state machine"],
                    "modeled": [
                        "packet arrival",
                        "device and CPU memory views",
                        "transfer completion",
                        "explicit synchronization",
                        "active-transfer reset disposition",
                    ],
                    "not_claimed": [
                        "a particular DMA controller or interconnect implementation",
                        "wall-clock timing",
                        "physical cache coherence",
                        "physical-device behavior",
                    ],
                },
                "adaptations": [
                    "only the declared leading memory window is materialized",
                    "logical ticks are caller-supplied ordering labels, not hardware cycles",
                    "payload bytes are represented in the receipt only by length and digest",
                ],
            }
        )
