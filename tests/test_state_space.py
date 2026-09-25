from __future__ import annotations

import unittest

from verirehost.errors import RehostError
from verirehost.receipt import verify
from verirehost.state_space import Predicate, Transition, explore


def transition(
    name: str,
    *,
    requires: tuple[str, ...] = (),
    forbids: tuple[str, ...] = (),
    adds: tuple[str, ...] = (),
    removes: tuple[str, ...] = (),
) -> Transition:
    return Transition.from_dict(
        {
            "name": name,
            "requires": list(requires),
            "forbids": list(forbids),
            "adds": list(adds),
            "removes": list(removes),
        }
    )


class StateSpaceTests(unittest.TestCase):
    def test_exhaustive_search_records_shortest_goal_and_forbidden_witnesses(self) -> None:
        receipt = explore(
            model_id="synthetic-interlock",
            initial_atoms=["ready"],
            transitions=[
                transition("verify", requires=("ready",), adds=("verified",)),
                transition("publish", requires=("verified",), adds=("published",)),
                transition("unsafe_publish", requires=("ready",), adds=("published",)),
            ],
            goals=[
                Predicate.from_dict(
                    {"name": "published", "requires": ["published"]}
                )
            ],
            forbidden=[
                Predicate.from_dict(
                    {
                        "name": "unverified_publish",
                        "requires": ["published"],
                        "forbids": ["verified"],
                    }
                )
            ],
            assumptions=["events are synthetic"],
            max_depth=4,
            max_states=32,
        )

        verify(receipt)
        self.assertEqual(receipt["status"], "complete")
        goal = receipt["exploration"]["goals"][0]
        hazard = receipt["exploration"]["forbidden"][0]
        self.assertTrue(goal["reached"])
        self.assertTrue(hazard["reached"])
        self.assertEqual(goal["witness"][0]["transition"], "unsafe_publish")
        self.assertEqual(hazard["witness"][0]["transition"], "unsafe_publish")

    def test_transition_order_does_not_change_receipt(self) -> None:
        items = [
            transition("second", requires=("first",), adds=("done",)),
            transition("first", requires=("ready",), adds=("first",)),
        ]
        kwargs = {
            "model_id": "synthetic-order",
            "initial_atoms": ["ready"],
            "goals": [Predicate.from_dict({"name": "done", "requires": ["done"]})],
            "assumptions": ["transition order has no semantics"],
        }
        forward = explore(transitions=items, **kwargs)
        reverse = explore(transitions=reversed(items), **kwargs)
        self.assertEqual(forward["content_id"], reverse["content_id"])

    def test_depth_exhaustion_does_not_claim_goal_unreachable(self) -> None:
        receipt = explore(
            model_id="synthetic-depth-bound",
            initial_atoms=["ready"],
            transitions=[
                transition("first", requires=("ready",), adds=("middle",)),
                transition("second", requires=("middle",), adds=("done",)),
            ],
            goals=[Predicate.from_dict({"name": "done", "requires": ["done"]})],
            max_depth=1,
        )
        self.assertEqual(receipt["status"], "budget_exhausted")
        self.assertFalse(receipt["exploration"]["complete"])
        self.assertFalse(receipt["exploration"]["goals"][0]["reached"])

    def test_invalid_transition_fails_closed(self) -> None:
        with self.assertRaisesRegex(RehostError, "STATE_TRANSITION"):
            Transition.from_dict(
                {"name": "bad", "adds": ["same"], "removes": ["same"]}
            )

    def test_invalid_budget_and_assumption_types_fail_closed(self) -> None:
        kwargs = {
            "model_id": "synthetic-validation",
            "initial_atoms": [],
            "transitions": [transition("begin", adds=("done",))],
            "goals": [Predicate.from_dict({"name": "done", "requires": ["done"]})],
        }
        with self.assertRaisesRegex(RehostError, "STATE_BUDGET"):
            explore(max_depth=True, **kwargs)
        with self.assertRaisesRegex(RehostError, "STATE_ASSUMPTIONS"):
            explore(assumptions="not-a-list", **kwargs)


if __name__ == "__main__":
    unittest.main()
