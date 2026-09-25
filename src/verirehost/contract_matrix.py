from __future__ import annotations

import itertools
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from . import __version__
from .canonical import sha256_object
from .errors import RehostError
from .receipt import seal


MAX_MATRIX_ROWS = 4096
_NAME = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")


class TruthValue(StrEnum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ContractAxis:
    name: str
    variants: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.name):
            raise ValueError("contract axis name must be a portable lowercase identifier")
        if len(self.variants) < 2 or len(self.variants) != len(set(self.variants)):
            raise ValueError("contract axis must declare at least two unique variants")
        if not all(_NAME.fullmatch(value) for value in self.variants):
            raise ValueError("contract variants must be portable lowercase identifiers")

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "variants": list(self.variants)}


@dataclass(frozen=True, slots=True)
class ContractOutcome:
    outcomes: Mapping[str, TruthValue]
    trace: tuple[str, ...] = ()
    observations: Mapping[str, Any] | None = None
    evidence_refs: tuple[str, ...] = ()


Evaluator = Callable[[Mapping[str, str]], ContractOutcome]


def _portable(value: Any, field: str) -> Any:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise RehostError(
            "CONTRACT_VALUE",
            "contract observations must contain deterministic JSON values",
            {"field": field},
        ) from exc


def _normalize_outcome(
    value: ContractOutcome,
    expected_names: tuple[str, ...] | None,
) -> tuple[dict[str, Any], tuple[str, ...]]:
    if not isinstance(value, ContractOutcome):
        raise RehostError("CONTRACT_OUTCOME", "contract evaluator returned an invalid outcome")
    if not value.outcomes:
        raise RehostError("CONTRACT_OUTCOME", "contract outcome must not be empty")
    names = tuple(sorted(value.outcomes))
    if expected_names is not None and names != expected_names:
        raise RehostError(
            "CONTRACT_OUTCOME",
            "every matrix row must report the same outcome names",
            {"expected": list(expected_names), "observed": list(names)},
        )
    normalized: dict[str, str] = {}
    for name in names:
        if not _NAME.fullmatch(name):
            raise RehostError("CONTRACT_OUTCOME", "outcome names must be portable identifiers")
        result = value.outcomes[name]
        if not isinstance(result, TruthValue):
            raise RehostError("CONTRACT_OUTCOME", "outcome values must be TruthValue members")
        normalized[name] = result.value
    if not all(isinstance(item, str) and item for item in value.trace):
        raise RehostError("CONTRACT_TRACE", "contract trace entries must be non-empty strings")
    if not all(isinstance(item, str) and item for item in value.evidence_refs):
        raise RehostError("CONTRACT_EVIDENCE", "evidence references must be non-empty strings")
    row = {
        "outcomes": normalized,
        "trace": list(value.trace),
        "observations": _portable(value.observations or {}, "observations"),
        "evidence_refs": sorted(set(value.evidence_refs)),
    }
    return row, names


def _aggregate(
    outcome_name: str,
    axes: tuple[ContractAxis, ...],
    rows: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    counts = {
        value.value: sum(row["outcomes"][outcome_name] == value.value for row in rows)
        for value in TruthValue
    }
    true_rows = [row for row in rows if row["outcomes"][outcome_name] == TruthValue.TRUE]
    necessary: dict[str, list[str]] = {}
    if true_rows:
        for axis in axes:
            observed = sorted({row["assignment"][axis.name] for row in true_rows})
            if len(observed) == 1:
                necessary[axis.name] = observed

    influential: list[str] = []
    for axis in axes:
        other_names = [item.name for item in axes if item.name != axis.name]
        buckets: dict[tuple[str, ...], set[str]] = {}
        for row in rows:
            key = tuple(row["assignment"][name] for name in other_names)
            buckets.setdefault(key, set()).add(row["outcomes"][outcome_name])
        if any(len(results) > 1 for results in buckets.values()):
            influential.append(axis.name)

    first_false = next(
        (row["assignment"] for row in rows if row["outcomes"][outcome_name] == TruthValue.FALSE),
        None,
    )
    first_unknown = next(
        (row["assignment"] for row in rows if row["outcomes"][outcome_name] == TruthValue.UNKNOWN),
        None,
    )
    return {
        "counts": counts,
        "conclusive": counts[TruthValue.UNKNOWN] == 0,
        "universally_true": counts[TruthValue.TRUE] == len(rows),
        "possibly_true": counts[TruthValue.TRUE] > 0,
        "necessary_variants_among_true_rows": necessary,
        "influential_axes": influential,
        "first_false_assignment": first_false,
        "first_unknown_assignment": first_unknown,
    }


def evaluate_contract_matrix(
    *,
    model_id: str,
    evaluator_id: str,
    axes: Sequence[ContractAxis],
    evaluator: Evaluator,
    assumptions: Sequence[str] = (),
    max_rows: int = MAX_MATRIX_ROWS,
) -> dict[str, Any]:
    """Exhaustively evaluate a finite hardware-contract policy product.

    The evaluator owns all semantics. The public matrix engine records true,
    false, and unknown separately and never converts an unknown policy into a
    deny or success. Results are conclusive only for the declared finite policy
    product, not for unmodeled physical hardware.
    """

    if not _NAME.fullmatch(model_id) or not _NAME.fullmatch(evaluator_id):
        raise RehostError("CONTRACT_NAME", "model and evaluator IDs must be portable names")
    axis_items = tuple(sorted(axes, key=lambda item: item.name))
    if not axis_items or not all(isinstance(item, ContractAxis) for item in axis_items):
        raise RehostError("CONTRACT_AXES", "at least one ContractAxis is required")
    if len({item.name for item in axis_items}) != len(axis_items):
        raise RehostError("CONTRACT_AXES", "contract axis names must be unique")
    row_count = 1
    for axis in axis_items:
        row_count *= len(axis.variants)
    if (
        isinstance(max_rows, bool)
        or not isinstance(max_rows, int)
        or not 1 <= max_rows <= MAX_MATRIX_ROWS
        or row_count > max_rows
    ):
        raise RehostError(
            "CONTRACT_BUDGET",
            "contract policy product exceeds the declared row budget",
            {"rows": row_count, "maximum_rows": max_rows},
        )
    if not callable(evaluator):
        raise RehostError("CONTRACT_EVALUATOR", "contract evaluator must be callable")
    if not all(isinstance(item, str) and item for item in assumptions):
        raise RehostError("CONTRACT_ASSUMPTIONS", "assumptions must be non-empty strings")

    rows: list[dict[str, Any]] = []
    outcome_names: tuple[str, ...] | None = None
    variants = [axis.variants for axis in axis_items]
    for row_index, values in enumerate(itertools.product(*variants)):
        assignment = {
            axis.name: value for axis, value in zip(axis_items, values, strict=True)
        }
        result, names = _normalize_outcome(
            evaluator(MappingProxyType(assignment)), outcome_names
        )
        outcome_names = names
        result["row"] = row_index
        result["assignment"] = assignment
        result["row_sha256"] = sha256_object(
            {"assignment": assignment, "outcomes": result["outcomes"]}
        )
        rows.append(result)

    assert outcome_names is not None
    aggregates = {
        name: _aggregate(name, axis_items, rows) for name in outcome_names
    }
    return seal(
        {
            "kind": "hardware_contract_policy_matrix",
            "tool": {"name": "verirehost", "version": __version__},
            "target": {"id": model_id, "kind": "abstract_hardware_contract"},
            "claim_grade": "synthetic_model",
            "status": "complete",
            "evaluator_id": evaluator_id,
            "axes": [axis.as_dict() for axis in axis_items],
            "assumptions": list(assumptions),
            "matrix": rows,
            "analysis": {
                "rows_exhausted": len(rows),
                "row_budget": max_rows,
                "matrix_sha256": sha256_object(rows),
                "outcomes": aggregates,
            },
            "claims": [
                {
                    "id": "finite-contract-matrix-observation",
                    "statement": (
                        "Every declared policy combination was evaluated and unknown "
                        "outcomes remained distinct from success and failure."
                    ),
                    "grade": "synthetic_model",
                }
            ],
            "model_boundary": {
                "executed": ["VeriRehost finite contract-matrix evaluator"],
                "modeled": ["caller-declared policy axes and evaluator semantics"],
                "not_claimed": [
                    "completeness of the caller's policy variants",
                    "physical-device behavior",
                    "wall-clock exploitability",
                    "physical irreversible-state preservation",
                ],
            },
            "adaptations": [
                "axis order is normalized by name",
                "the full Cartesian policy product is evaluated",
                "unknown is not interpreted as false or safe",
                *assumptions,
            ],
        }
    )
