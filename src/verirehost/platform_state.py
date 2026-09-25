from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from . import __version__
from .errors import RehostError
from .receipt import seal


class PersistentDisposition(StrEnum):
    FLUSH_STAGED = "flush_staged"
    DISCARD_STAGED = "discard_staged"
    PRESERVE_STAGED = "preserve_staged"


@dataclass(frozen=True, slots=True)
class ResetPolicy:
    name: str
    preserve_retention: bool
    persistent_disposition: PersistentDisposition
    honor_reentry_request: bool

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("reset policy name must be non-empty")
        if not isinstance(self.persistent_disposition, PersistentDisposition):
            raise ValueError("persistent_disposition must be a PersistentDisposition")

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "preserve_retention": self.preserve_retention,
            "persistent_disposition": self.persistent_disposition.value,
            "honor_reentry_request": self.honor_reentry_request,
        }


def _portable(value: Any, field: str) -> Any:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise RehostError(
            "PLATFORM_VALUE",
            "platform state values must be deterministic JSON",
            {"field": field},
        ) from exc


class PlatformState:
    """Multi-boot state with explicit volatile, retention, and storage domains."""

    def __init__(self, *, default_boot_mode: str = "normal") -> None:
        if not isinstance(default_boot_mode, str) or not default_boot_mode.strip():
            raise ValueError("default_boot_mode must be non-empty")
        self.default_boot_mode = default_boot_mode
        self.boot_mode = default_boot_mode
        self.boot_count = 1
        self.reset_count = 0
        self.volatile: dict[str, Any] = {}
        self.retention: dict[str, Any] = {}
        self.committed: dict[str, Any] = {}
        self.staged: dict[str, Any] = {}
        self._reentry_request: str | None = None
        self._events: list[dict[str, Any]] = [
            {"kind": "boot", "boot_count": 1, "mode": default_boot_mode}
        ]

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._events)

    def set_volatile(self, key: str, value: Any) -> None:
        self.volatile[key] = _portable(value, f"volatile.{key}")

    def set_retention(self, key: str, value: Any) -> None:
        self.retention[key] = _portable(value, f"retention.{key}")

    def stage_persistent(self, key: str, value: Any) -> None:
        self.staged[key] = _portable(value, f"staged.{key}")
        self._events.append({"kind": "persistent_stage", "key": key})

    def flush_persistent(self, key: str | None = None) -> None:
        keys = sorted(self.staged) if key is None else [key]
        for item in keys:
            if item not in self.staged:
                raise RehostError(
                    "PLATFORM_FLUSH",
                    "cannot flush a key with no staged value",
                    {"key": item},
                )
            self.committed[item] = self.staged.pop(item)
            self._events.append({"kind": "persistent_flush", "key": item})

    def request_reentry(self, mode: str) -> None:
        if not isinstance(mode, str) or not mode.strip():
            raise ValueError("reentry mode must be non-empty")
        self._reentry_request = mode
        self._events.append({"kind": "reentry_request", "mode": mode})

    def reset(self, *, reason: str, policy: ResetPolicy) -> str:
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("reset reason must be non-empty")
        if policy.persistent_disposition == PersistentDisposition.FLUSH_STAGED:
            self.flush_persistent()
        elif policy.persistent_disposition == PersistentDisposition.DISCARD_STAGED:
            discarded = sorted(self.staged)
            self.staged.clear()
            self._events.append({"kind": "persistent_discard", "keys": discarded})

        requested_mode = self._reentry_request
        selected_mode = (
            requested_mode
            if requested_mode is not None and policy.honor_reentry_request
            else self.default_boot_mode
        )
        self.volatile.clear()
        if not policy.preserve_retention:
            self.retention.clear()
        self._reentry_request = None
        self.reset_count += 1
        self.boot_count += 1
        self.boot_mode = selected_mode
        self._events.append(
            {
                "kind": "reset",
                "reason": reason,
                "policy": policy.as_dict(),
                "requested_mode": requested_mode,
                "selected_mode": selected_mode,
                "boot_count": self.boot_count,
            }
        )
        return selected_mode

    def snapshot(self) -> dict[str, Any]:
        return {
            "boot_count": self.boot_count,
            "reset_count": self.reset_count,
            "boot_mode": self.boot_mode,
            "volatile": copy.deepcopy(self.volatile),
            "retention": copy.deepcopy(self.retention),
            "persistent_committed": copy.deepcopy(self.committed),
            "persistent_staged": copy.deepcopy(self.staged),
            "reentry_request": self._reentry_request,
        }

    def receipt(self, *, model_id: str, policies: list[ResetPolicy]) -> dict[str, Any]:
        return seal(
            {
                "kind": "multi_boot_platform_state_model",
                "tool": {"name": "verirehost", "version": __version__},
                "target": {"id": model_id, "kind": "synthetic_reset_contract"},
                "claim_grade": "synthetic_model",
                "status": "complete",
                "declared_reset_policies": [item.as_dict() for item in policies],
                "events": list(self._events),
                "result": self.snapshot(),
                "claims": [
                    {
                        "id": "declared-reset-state-observation",
                        "statement": (
                            "Volatile, retention, staged, and committed state followed "
                            "the explicitly declared reset policies."
                        ),
                        "grade": "synthetic_model",
                    }
                ],
                "model_boundary": {
                    "executed": ["VeriRehost multi-boot platform state machine"],
                    "modeled": [
                        "volatile state loss",
                        "retention preservation",
                        "staged storage flush or discard",
                        "requested boot-mode reentry",
                    ],
                    "not_claimed": [
                        "a particular PMU or reset controller",
                        "physical storage durability",
                        "boot ROM behavior",
                        "physical-device reentry",
                    ],
                },
                "adaptations": [
                    "state values are restricted to deterministic JSON",
                    "reset and boot occur atomically in the public model",
                ],
            }
        )
