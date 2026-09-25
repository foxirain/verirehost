from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from . import __version__
from .errors import RehostError
from .receipt import seal
from .smc_router import SideEffect


MAX_OTP_BITS = 4096


class OtpDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class OtpRule:
    name: str
    decision: OtpDecision
    required_context: tuple[tuple[str, str], ...] = ()
    allowed_set_mask: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("OTP rule name must be non-empty")
        if not isinstance(self.decision, OtpDecision):
            raise ValueError("OTP rule decision must be an OtpDecision")
        keys = [key for key, _ in self.required_context]
        if len(keys) != len(set(keys)):
            raise ValueError("OTP rule context keys must be unique")
        if self.allowed_set_mask is not None and self.allowed_set_mask < 0:
            raise ValueError("OTP allowed_set_mask must be non-negative")

    @classmethod
    def from_context(
        cls,
        name: str,
        decision: OtpDecision,
        required_context: dict[str, str] | None = None,
        allowed_set_mask: int | None = None,
    ) -> "OtpRule":
        context = tuple(sorted((required_context or {}).items()))
        return cls(name, decision, context, allowed_set_mask)

    def matches(self, context: dict[str, str], set_mask: int) -> bool:
        if not all(context.get(key) == value for key, value in self.required_context):
            return False
        return self.allowed_set_mask is None or set_mask & ~self.allowed_set_mask == 0

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "name": self.name,
            "decision": self.decision.value,
            "required_context": dict(self.required_context),
        }
        if self.allowed_set_mask is not None:
            value["allowed_set_mask"] = f"0x{self.allowed_set_mask:x}"
        return value


@dataclass(frozen=True, slots=True)
class OtpRequestResult:
    decision: OtpDecision
    changed_mask: int
    state: int
    rule: str | None


class MonotonicOtp:
    """One-way OTP/fuse model with explicit allow, deny, and unknown outcomes."""

    def __init__(
        self,
        *,
        width: int,
        policy_id: str,
        rules: tuple[OtpRule, ...],
        default_decision: OtpDecision = OtpDecision.UNKNOWN,
        initial_state: int = 0,
        effect: SideEffect = SideEffect.OTP,
    ) -> None:
        if isinstance(width, bool) or not isinstance(width, int) or not 1 <= width <= MAX_OTP_BITS:
            raise ValueError(f"OTP width must be between 1 and {MAX_OTP_BITS}")
        if not isinstance(policy_id, str) or not policy_id.strip():
            raise ValueError("OTP policy_id must be non-empty")
        if not isinstance(default_decision, OtpDecision):
            raise ValueError("default_decision must be an OtpDecision")
        if effect not in {SideEffect.OTP, SideEffect.FUSE}:
            raise ValueError("OTP effect must be SideEffect.OTP or SideEffect.FUSE")
        maximum = (1 << width) - 1
        if initial_state < 0 or initial_state > maximum:
            raise ValueError("OTP initial_state does not fit the declared width")
        names = [rule.name for rule in rules]
        if len(names) != len(set(names)):
            raise ValueError("OTP rule names must be unique")
        if any(
            rule.allowed_set_mask is not None and rule.allowed_set_mask > maximum
            for rule in rules
        ):
            raise ValueError("OTP rule mask does not fit the declared width")

        self.width = width
        self.policy_id = policy_id
        self.rules = rules
        self.default_decision = default_decision
        self.effect = effect
        self._maximum = maximum
        self._initial_state = initial_state
        self._state = initial_state
        self._events: list[dict[str, Any]] = []

    @property
    def state(self) -> int:
        return self._state

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._events)

    def request_program(
        self,
        *,
        set_mask: int,
        context: dict[str, str],
        clear_mask: int = 0,
    ) -> OtpRequestResult:
        if set_mask < 0 or set_mask > self._maximum:
            raise RehostError("OTP_MASK", "OTP set mask does not fit the declared width")
        if clear_mask:
            raise RehostError(
                "OTP_ONE_WAY",
                "OTP bits cannot transition from programmed to clear",
                {"clear_mask": f"0x{clear_mask:x}"},
            )
        if not isinstance(context, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in context.items()
        ):
            raise RehostError("OTP_CONTEXT", "OTP context must map strings to strings")
        matches = [rule for rule in self.rules if rule.matches(context, set_mask)]
        if len(matches) > 1:
            raise RehostError(
                "OTP_POLICY_AMBIGUOUS",
                "OTP request matches multiple declared rules",
                {"rules": sorted(rule.name for rule in matches)},
            )
        rule = matches[0] if matches else None
        decision = rule.decision if rule is not None else self.default_decision
        before = self._state
        if decision == OtpDecision.ALLOW:
            self._state |= set_mask
        changed = before ^ self._state
        event = {
            "kind": "program_request",
            "context": dict(sorted(context.items())),
            "set_mask": f"0x{set_mask:x}",
            "decision": decision.value,
            "rule": rule.name if rule is not None else None,
            "before": f"0x{before:x}",
            "after": f"0x{self._state:x}",
            "changed_mask": f"0x{changed:x}",
            "modeled_effect": self.effect.value if changed else None,
        }
        self._events.append(event)
        return OtpRequestResult(decision, changed, self._state, event["rule"])

    def receipt(self, *, model_id: str) -> dict[str, Any]:
        return seal(
            {
                "kind": "monotonic_otp_policy_model",
                "tool": {"name": "verirehost", "version": __version__},
                "target": {"id": model_id, "kind": "synthetic_irreversible_state"},
                "claim_grade": "synthetic_model",
                "status": "complete",
                "policy": {
                    "id": self.policy_id,
                    "width": self.width,
                    "effect": self.effect.value,
                    "default_decision": self.default_decision.value,
                    "rules": [rule.as_dict() for rule in self.rules],
                },
                "events": list(self._events),
                "result": {
                    "initial_state": f"0x{self._initial_state:x}",
                    "final_state": f"0x{self._state:x}",
                    "changed_mask": f"0x{self._initial_state ^ self._state:x}",
                },
                "claims": [
                    {
                        "id": "declared-otp-policy-observation",
                        "statement": (
                            "The modeled irreversible state followed the declared "
                            "allow, deny, or unknown OTP policy."
                        ),
                        "grade": "synthetic_model",
                    }
                ],
                "model_boundary": {
                    "executed": ["VeriRehost monotonic OTP state machine"],
                    "modeled": ["one-way bit programming", "context rules", "unknown policy"],
                    "not_claimed": [
                        "vendor secure-monitor authorization",
                        "physical OTP controller behavior",
                        "physical fuse state",
                    ],
                },
                "adaptations": [
                    "unknown policy is distinct from deny",
                    "overlapping authorization rules fail closed",
                    "bit clearing is rejected",
                ],
            }
        )
