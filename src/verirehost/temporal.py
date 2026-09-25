from __future__ import annotations

import heapq
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from .canonical import sha256_object
from .errors import RehostError


MAX_EVENTS = 100_000
MAX_TICK = (1 << 63) - 1


class EventPhase(IntEnum):
    """Stable ordering for events that share one logical clock tick."""

    DEVICE = 10
    DMA = 20
    COHERENCE = 30
    INTERRUPT = 40
    SOFTWARE = 50
    RESET = 60


EventAction = Callable[["DeterministicScheduler"], Mapping[str, Any] | None]


@dataclass(order=True, slots=True)
class _QueuedEvent:
    tick: int
    phase: int
    sequence: int
    name: str = field(compare=False)
    action: EventAction = field(compare=False, repr=False)


def _portable_details(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise RehostError("TIME_EVENT_RESULT", "event result must be a mapping or null")
    result = dict(value)
    try:
        json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise RehostError(
            "TIME_EVENT_RESULT",
            "event result must contain deterministic JSON values",
        ) from exc
    return result


class DeterministicScheduler:
    """Bounded logical-time scheduler with explicit same-tick causality.

    Events are ordered by ``(tick, phase, insertion sequence)``. An event may
    schedule later work, including work in a later phase of its current tick,
    but it cannot schedule backwards into an earlier phase. This makes device,
    DMA, coherence, interrupt, software, and reset ordering inspectable without
    pretending that logical ticks are wall-clock cycles.
    """

    def __init__(self, *, max_events: int = 4096) -> None:
        if isinstance(max_events, bool) or not 1 <= max_events <= MAX_EVENTS:
            raise ValueError(f"max_events must be between 1 and {MAX_EVENTS}")
        self.max_events = max_events
        self.now = 0
        self.phase: EventPhase | None = None
        self._sequence = 0
        self._executed = 0
        self._queue: list[_QueuedEvent] = []
        self._trace: list[dict[str, Any]] = []

    @property
    def pending(self) -> int:
        return len(self._queue)

    @property
    def trace(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._trace)

    def schedule_at(
        self,
        tick: int,
        phase: EventPhase,
        name: str,
        action: EventAction,
    ) -> None:
        if isinstance(tick, bool) or not isinstance(tick, int) or not 0 <= tick <= MAX_TICK:
            raise RehostError("TIME_TICK", "event tick is outside the supported range")
        if not isinstance(phase, EventPhase):
            raise RehostError("TIME_PHASE", "event phase must be an EventPhase")
        if not isinstance(name, str) or not name.strip():
            raise RehostError("TIME_EVENT_NAME", "event name must be non-empty")
        if not callable(action):
            raise RehostError("TIME_EVENT_ACTION", "event action must be callable")
        if tick < self.now:
            raise RehostError("TIME_CAUSALITY", "an event cannot be scheduled in the past")
        if tick == self.now and self.phase is not None and phase < self.phase:
            raise RehostError(
                "TIME_CAUSALITY",
                "an event cannot schedule an earlier phase in the current tick",
                {
                    "current_phase": self.phase.name.lower(),
                    "requested_phase": phase.name.lower(),
                },
            )
        self._sequence += 1
        heapq.heappush(
            self._queue,
            _QueuedEvent(tick, int(phase), self._sequence, name, action),
        )

    def schedule_after(
        self,
        delay: int,
        phase: EventPhase,
        name: str,
        action: EventAction,
    ) -> None:
        if isinstance(delay, bool) or not isinstance(delay, int) or delay < 0:
            raise RehostError("TIME_DELAY", "event delay must be a non-negative integer")
        self.schedule_at(self.now + delay, phase, name, action)

    def run(self, *, through_tick: int | None = None) -> tuple[dict[str, Any], ...]:
        if through_tick is not None and (
            isinstance(through_tick, bool)
            or not isinstance(through_tick, int)
            or through_tick < self.now
            or through_tick > MAX_TICK
        ):
            raise RehostError("TIME_TICK", "run boundary is outside the supported range")
        while self._queue:
            event = self._queue[0]
            if through_tick is not None and event.tick > through_tick:
                break
            if self._executed >= self.max_events:
                raise RehostError(
                    "TIME_BUDGET",
                    "logical-time event budget exhausted",
                    {"maximum_events": self.max_events, "pending_events": len(self._queue)},
                )
            heapq.heappop(self._queue)
            self.now = event.tick
            self.phase = EventPhase(event.phase)
            details = _portable_details(event.action(self))
            self._executed += 1
            self._trace.append(
                {
                    "sequence": self._executed,
                    "tick": self.now,
                    "phase": self.phase.name.lower(),
                    "name": event.name,
                    "details": details,
                }
            )
        self.phase = None
        return self.trace

    def summary(self) -> dict[str, Any]:
        return {
            "logical_clock": self.now,
            "events_executed": self._executed,
            "events_pending": len(self._queue),
            "maximum_events": self.max_events,
            "trace_sha256": sha256_object(self._trace),
        }
