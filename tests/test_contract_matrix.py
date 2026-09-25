from __future__ import annotations

import unittest

from verirehost.contract_matrix import (
    ContractAxis,
    ContractOutcome,
    TruthValue,
    evaluate_contract_matrix,
)
from verirehost.receipt import verify


class ContractMatrixTests(unittest.TestCase):
    def test_exhausts_product_and_preserves_unknown(self) -> None:
        axes = (
            ContractAxis("admission", ("allow", "deny", "unknown")),
            ContractAxis("visibility", ("completion", "packet", "unknown")),
        )

        def evaluator(assignment: dict[str, str]) -> ContractOutcome:
            if "unknown" in assignment.values():
                value = TruthValue.UNKNOWN
            elif assignment == {"admission": "allow", "visibility": "packet"}:
                value = TruthValue.TRUE
            else:
                value = TruthValue.FALSE
            return ContractOutcome(
                {"observation": value},
                trace=("synthetic-evaluation",),
                observations={"selected": dict(assignment)},
            )

        receipt = evaluate_contract_matrix(
            model_id="synthetic-contract",
            evaluator_id="synthetic-evaluator-v1",
            axes=axes,
            evaluator=evaluator,
            assumptions=("all semantics are synthetic",),
        )
        verify(receipt)
        self.assertEqual(receipt["analysis"]["rows_exhausted"], 9)
        analysis = receipt["analysis"]["outcomes"]["observation"]
        self.assertEqual(analysis["counts"], {"false": 3, "true": 1, "unknown": 5})
        self.assertFalse(analysis["conclusive"])
        self.assertEqual(
            analysis["necessary_variants_among_true_rows"],
            {"admission": ["allow"], "visibility": ["packet"]},
        )
        self.assertEqual(analysis["influential_axes"], ["admission", "visibility"])

    def test_outcome_shape_drift_fails_closed(self) -> None:
        calls = 0

        def evaluator(_assignment: dict[str, str]) -> ContractOutcome:
            nonlocal calls
            calls += 1
            name = "first" if calls == 1 else "second"
            return ContractOutcome({name: TruthValue.TRUE})

        with self.assertRaisesRegex(Exception, "same outcome names"):
            evaluate_contract_matrix(
                model_id="synthetic-contract",
                evaluator_id="synthetic-evaluator-v1",
                axes=(ContractAxis("gate", ("closed", "open")),),
                evaluator=evaluator,
            )


if __name__ == "__main__":
    unittest.main()
