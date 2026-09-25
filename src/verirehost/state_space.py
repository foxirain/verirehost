from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from . import __version__
from .canonical import sha256_object
from .errors import RehostError
from .receipt import seal


SCENARIO_SCHEMA = "verirehost/state-space-scenario/v1"
MAX_DEPTH = 64
MAX_STATES = 100_000
MAX_TRANSITIONS = 512
_NAME = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")


def _name(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise RehostError(
            "STATE_NAME",
            "state-space names must use lowercase portable identifiers",
            {"field": field},
        )
    return value


def _atom_set(values: Any, field: str) -> frozenset[str]:
    if not isinstance(values, (list, tuple, set, frozenset)):
        raise RehostError(
            "STATE_ATOMS", "state atoms must be a sequence", {"field": field}
        )
    atoms = [_name(value, field) for value in values]
    if len(atoms) != len(set(atoms)):
        raise RehostError(
            "STATE_ATOMS", "state atoms must not contain duplicates", {"field": field}
        )
    return frozenset(atoms)


@dataclass(frozen=True, slots=True)
class Predicate:
    name: str
    requires: frozenset[str]
    forbids: frozenset[str]

    @classmethod
    def from_dict(cls, value: Any, field: str = "predicate") -> "Predicate":
        if not isinstance(value, dict):
            raise RehostError("STATE_PREDICATE", "predicate must be an object")
        unknown = set(value) - {"name", "requires", "forbids"}
        if unknown:
            raise RehostError(
                "STATE_PREDICATE",
                "predicate contains unknown fields",
                {"fields": sorted(unknown)},
            )
        name = _name(value.get("name"), f"{field}.name")
        requires = _atom_set(value.get("requires", []), f"{field}.requires")
        forbids = _atom_set(value.get("forbids", []), f"{field}.forbids")
        if requires & forbids:
            raise RehostError(
                "STATE_PREDICATE",
                "predicate cannot require and forbid the same atom",
                {"name": name, "atoms": sorted(requires & forbids)},
            )
        return cls(name=name, requires=requires, forbids=forbids)

    def matches(self, state: frozenset[str]) -> bool:
        return self.requires <= state and not self.forbids & state

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "requires": sorted(self.requires),
            "forbids": sorted(self.forbids),
        }


@dataclass(frozen=True, slots=True)
class Transition:
    name: str
    requires: frozenset[str]
    forbids: frozenset[str]
    adds: frozenset[str]
    removes: frozenset[str]

    @classmethod
    def from_dict(cls, value: Any, field: str = "transition") -> "Transition":
        if not isinstance(value, dict):
            raise RehostError("STATE_TRANSITION", "transition must be an object")
        unknown = set(value) - {"name", "requires", "forbids", "adds", "removes"}
        if unknown:
            raise RehostError(
                "STATE_TRANSITION",
                "transition contains unknown fields",
                {"fields": sorted(unknown)},
            )
        name = _name(value.get("name"), f"{field}.name")
        requires = _atom_set(value.get("requires", []), f"{field}.requires")
        forbids = _atom_set(value.get("forbids", []), f"{field}.forbids")
        adds = _atom_set(value.get("adds", []), f"{field}.adds")
        removes = _atom_set(value.get("removes", []), f"{field}.removes")
        if requires & forbids:
            raise RehostError(
                "STATE_TRANSITION",
                "transition cannot require and forbid the same atom",
                {"name": name, "atoms": sorted(requires & forbids)},
            )
        if adds & removes:
            raise RehostError(
                "STATE_TRANSITION",
                "transition cannot add and remove the same atom",
                {"name": name, "atoms": sorted(adds & removes)},
            )
        if not adds and not removes:
            raise RehostError(
                "STATE_TRANSITION",
                "transition must change at least one atom",
                {"name": name},
            )
        return cls(
            name=name,
            requires=requires,
            forbids=forbids,
            adds=adds,
            removes=removes,
        )

    def enabled(self, state: frozenset[str]) -> bool:
        return self.requires <= state and not self.forbids & state

    def apply(self, state: frozenset[str]) -> frozenset[str]:
        return (state - self.removes) | self.adds

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "requires": sorted(self.requires),
            "forbids": sorted(self.forbids),
            "adds": sorted(self.adds),
            "removes": sorted(self.removes),
        }


def _state_id(state: frozenset[str]) -> str:
    return f"sha256:{sha256_object(sorted(state))}"


def _trace_event(
    step: int,
    transition: Transition,
    before: frozenset[str],
    after: frozenset[str],
) -> dict[str, Any]:
    return {
        "step": step,
        "transition": transition.name,
        "before": _state_id(before),
        "after": _state_id(after),
        "added": sorted(after - before),
        "removed": sorted(before - after),
    }


def _predicate_results(
    predicates: tuple[Predicate, ...],
    witnesses: dict[frozenset[str], tuple[dict[str, Any], ...]],
) -> list[dict[str, Any]]:
    ordered_states = sorted(witnesses, key=lambda state: (len(witnesses[state]), sorted(state)))
    results: list[dict[str, Any]] = []
    for predicate in predicates:
        matched = next((state for state in ordered_states if predicate.matches(state)), None)
        results.append(
            {
                "name": predicate.name,
                "reached": matched is not None,
                "state": sorted(matched) if matched is not None else None,
                "state_id": _state_id(matched) if matched is not None else None,
                "witness": list(witnesses[matched]) if matched is not None else None,
            }
        )
    return results


def explore(
    *,
    model_id: str,
    initial_atoms: Iterable[str],
    transitions: Iterable[Transition],
    goals: Iterable[Predicate],
    forbidden: Iterable[Predicate] = (),
    assumptions: Iterable[str] = (),
    max_depth: int = 16,
    max_states: int = 4096,
) -> dict[str, Any]:
    """Exhaustively explore a finite, target-neutral transition system.

    Atoms have no built-in firmware or peripheral meaning. Callers own those
    semantics and must list them as assumptions. An incomplete search never
    promotes an unreached goal into an impossibility claim.
    """

    model_id = _name(model_id, "id")
    initial = _atom_set(list(initial_atoms), "initial_atoms")
    transition_items = tuple(transitions)
    goal_items = tuple(goals)
    forbidden_items = tuple(forbidden)
    if not all(isinstance(item, Transition) for item in transition_items):
        raise RehostError("STATE_TRANSITIONS", "transitions must be Transition objects")
    if not all(isinstance(item, Predicate) for item in (*goal_items, *forbidden_items)):
        raise RehostError("STATE_PREDICATE", "goals and forbidden must be Predicate objects")
    ordered_transitions = tuple(sorted(transition_items, key=lambda item: item.name))
    ordered_goals = tuple(sorted(goal_items, key=lambda item: item.name))
    ordered_forbidden = tuple(sorted(forbidden_items, key=lambda item: item.name))
    if isinstance(assumptions, (str, bytes)):
        raise RehostError("STATE_ASSUMPTIONS", "assumptions must be a sequence of strings")
    declared_assumptions = tuple(assumptions)

    if not ordered_transitions or len(ordered_transitions) > MAX_TRANSITIONS:
        raise RehostError(
            "STATE_TRANSITIONS",
            "transition count is outside the supported range",
            {"maximum": MAX_TRANSITIONS, "observed": len(ordered_transitions)},
        )
    names = [transition.name for transition in ordered_transitions]
    if len(names) != len(set(names)):
        raise RehostError("STATE_TRANSITIONS", "transition names must be unique")
    predicate_names = [item.name for item in (*ordered_goals, *ordered_forbidden)]
    if len(predicate_names) != len(set(predicate_names)):
        raise RehostError("STATE_PREDICATE", "goal and forbidden names must be unique")
    if not ordered_goals:
        raise RehostError("STATE_GOALS", "at least one goal predicate is required")
    if (
        isinstance(max_depth, bool)
        or not isinstance(max_depth, int)
        or not 0 <= max_depth <= MAX_DEPTH
    ):
        raise RehostError(
            "STATE_BUDGET",
            "maximum depth is outside the supported range",
            {"maximum": MAX_DEPTH},
        )
    if (
        isinstance(max_states, bool)
        or not isinstance(max_states, int)
        or not 1 <= max_states <= MAX_STATES
    ):
        raise RehostError(
            "STATE_BUDGET",
            "maximum states is outside the supported range",
            {"maximum": MAX_STATES},
        )
    if not all(isinstance(value, str) and value for value in declared_assumptions):
        raise RehostError("STATE_ASSUMPTIONS", "assumptions must be non-empty strings")

    witnesses: dict[frozenset[str], tuple[dict[str, Any], ...]] = {initial: ()}
    frontier: deque[tuple[frozenset[str], int]] = deque([(initial, 0)])
    evaluated = 0
    enabled = 0
    maximum_observed_depth = 0
    complete = True
    stop_reason = "state_space_exhausted"

    while frontier:
        state, depth = frontier.popleft()
        maximum_observed_depth = max(maximum_observed_depth, depth)
        for transition in ordered_transitions:
            evaluated += 1
            if not transition.enabled(state):
                continue
            enabled += 1
            next_state = transition.apply(state)
            if next_state == state or next_state in witnesses:
                continue
            if depth >= max_depth:
                complete = False
                stop_reason = "maximum_depth_reached"
                continue
            if len(witnesses) >= max_states:
                complete = False
                stop_reason = "maximum_states_reached"
                frontier.clear()
                break
            trace = witnesses[state] + (
                _trace_event(depth + 1, transition, state, next_state),
            )
            witnesses[next_state] = trace
            frontier.append((next_state, depth + 1))

    goal_results = _predicate_results(ordered_goals, witnesses)
    forbidden_results = _predicate_results(ordered_forbidden, witnesses)
    return seal(
        {
            "kind": "deterministic_state_space_exploration",
            "tool": {"name": "verirehost", "version": __version__},
            "target": {"id": model_id, "kind": "abstract_state_machine"},
            "claim_grade": "synthetic_model",
            "status": "complete" if complete else "budget_exhausted",
            "model": {
                "initial_atoms": sorted(initial),
                "transitions": [item.as_dict() for item in ordered_transitions],
                "goals": [item.as_dict() for item in ordered_goals],
                "forbidden": [item.as_dict() for item in ordered_forbidden],
                "assumptions": list(declared_assumptions),
            },
            "budget": {
                "maximum_depth": max_depth,
                "maximum_states": max_states,
                "maximum_transitions": MAX_TRANSITIONS,
            },
            "exploration": {
                "complete": complete,
                "stop_reason": stop_reason,
                "states_reached": len(witnesses),
                "transitions_evaluated": evaluated,
                "transitions_enabled": enabled,
                "maximum_observed_depth": maximum_observed_depth,
                "goals": goal_results,
                "forbidden": forbidden_results,
            },
            "claims": [
                {
                    "id": "bounded-state-space-observation",
                    "statement": (
                        "The listed predicates have the recorded reachability "
                        "within this declared abstract transition model."
                    ),
                    "grade": "synthetic_model",
                }
            ],
            "model_boundary": {
                "executed": ["VeriRehost deterministic breadth-first scheduler"],
                "modeled": ["caller-declared atoms, guards, transitions, and predicates"],
                "not_claimed": [
                    "target firmware behavior",
                    "peripheral implementation or DMA coherence",
                    "physical timing or reset behavior",
                    "attacker reachability or security impact",
                ],
            },
            "adaptations": [
                "transition names are sorted before exploration",
                "states are deduplicated by their complete atom sets",
                "unreached goals are conclusive only when exploration.complete is true",
                *declared_assumptions,
            ],
        }
    )


def load_scenario(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RehostError(
            "STATE_SCENARIO_READ",
            "unable to read state-space scenario",
            {"path": str(path)},
        ) from exc
    if not isinstance(value, dict) or value.get("schema") != SCENARIO_SCHEMA:
        raise RehostError("STATE_SCENARIO_SCHEMA", "unsupported scenario schema")
    allowed = {
        "schema",
        "id",
        "initial_atoms",
        "transitions",
        "goals",
        "forbidden",
        "assumptions",
        "max_depth",
        "max_states",
    }
    unknown = set(value) - allowed
    if unknown:
        raise RehostError(
            "STATE_SCENARIO_FIELD",
            "scenario contains unknown fields",
            {"fields": sorted(unknown)},
        )
    return value


def explore_scenario(value: dict[str, Any]) -> dict[str, Any]:
    transitions_value = value.get("transitions")
    goals_value = value.get("goals")
    forbidden_value = value.get("forbidden", [])
    if not isinstance(transitions_value, list):
        raise RehostError("STATE_TRANSITIONS", "transitions must be a list")
    if not isinstance(goals_value, list):
        raise RehostError("STATE_GOALS", "goals must be a list")
    if not isinstance(forbidden_value, list):
        raise RehostError("STATE_PREDICATE", "forbidden predicates must be a list")
    return explore(
        model_id=value.get("id"),
        initial_atoms=value.get("initial_atoms", []),
        transitions=(
            Transition.from_dict(item, f"transitions[{index}]")
            for index, item in enumerate(transitions_value)
        ),
        goals=(
            Predicate.from_dict(item, f"goals[{index}]")
            for index, item in enumerate(goals_value)
        ),
        forbidden=(
            Predicate.from_dict(item, f"forbidden[{index}]")
            for index, item in enumerate(forbidden_value)
        ),
        assumptions=value.get("assumptions", []),
        max_depth=value.get("max_depth", 16),
        max_states=value.get("max_states", 4096),
    )
