"""Meta-optimizer: sequentially runs multiple sub-optimizers.

Passes the best result from one as seed to the next.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from superred.core.types.budget import BudgetEstimate, HierarchicalBudget
from superred.core.types.controllable import ControllableValue
from superred.core.types.feedback import FeedbackResult
from superred.core.types.observable import StaticObservable
from superred.core.types.threat_model import InterfaceSpec
from superred.core.types.trajectory import TraceEvent


class SequentialMetaOptimizer:
    """Runs sub-optimizers sequentially.

    Strategy:
        1. Run optimizer A until exhausted or budget fraction consumed
        2. Take A's best injection as seed for optimizer B
        3. Run B until exhausted or budget fraction consumed
        4. Repeat for all sub-optimizers
        5. If any improvement found, cycle through again
        6. Stop when full cycle yields no improvement
    """

    def __init__(
        self,
        children: list[Any],
        max_cycles: int = 3,
        budget_split: str = "equal",
    ):
        self._children = children
        self._max_cycles = max_cycles
        self._budget_split = budget_split
        self._current_child_idx = 0
        self._cycle = 0
        self._best_score: float = 0.0
        self._best_controllables: dict[str, Any] = {}
        self._cycle_improved = False
        self._goal: str = ""
        self._exhausted: bool = False

    # ---- OptimizerInterface ----

    def initialize(
        self,
        goal: str,
        controllables: list[InterfaceSpec],
        static_observables: list[StaticObservable],
        budget: HierarchicalBudget | None = None,
    ) -> None:
        self._goal = goal
        self._current_child_idx = 0
        self._cycle = 0
        self._best_score = 0.0
        self._best_controllables = {}
        self._cycle_improved = False
        self._exhausted = False
        for child in self._children:
            child.initialize(goal, controllables, static_observables, budget)

    def step(
        self,
        trace: Sequence[TraceEvent] | None = None,
        feedback: FeedbackResult | None = None,
    ) -> list[ControllableValue]:
        if feedback is not None:
            score = feedback.evaluation.primary_score.value
            if score > self._best_score:
                self._best_score = score
                self._cycle_improved = True

            if feedback.evaluation.success:
                self._exhausted = True
                return [ControllableValue(name=k, value=v) for k, v in self._best_controllables.items()]

        current_child = self._children[self._current_child_idx]
        child_values = current_child.step(trace=trace, feedback=feedback)

        if current_child.is_exhausted():
            self._current_child_idx += 1

            if self._current_child_idx >= len(self._children):
                self._current_child_idx = 0
                self._cycle += 1

                if not self._cycle_improved or self._cycle >= self._max_cycles:
                    self._exhausted = True
                    return child_values
                self._cycle_improved = False

            next_child = self._children[self._current_child_idx]
            next_child.initialize(
                self._goal, [], [], None
            )

        for cv in child_values:
            self._best_controllables[cv.name] = cv.value

        return child_values

    def is_exhausted(self) -> bool:
        return self._exhausted

    def receive_feedback(self, feedback: FeedbackResult) -> None:
        pass

    def estimate_budget(self) -> BudgetEstimate:
        total_iters = 0
        for child in self._children:
            est = child.estimate_budget()
            total_iters += est.estimated_iterations
        return BudgetEstimate(
            estimated_iterations=total_iters * self._max_cycles,
            confidence=0.3,
        )

    def get_sub_optimizers(self) -> list[Any]:
        return list(self._children)

    def teardown(self) -> None:
        for child in self._children:
            child.teardown()

    def get_metadata(self) -> dict[str, Any]:
        return {
            "type": "sequential_meta",
            "children": [c.get_name() for c in self._children],
            "max_cycles": self._max_cycles,
        }

    def get_name(self) -> str:
        child_names = " -> ".join(c.get_name() for c in self._children)
        return f"Sequential Meta ({child_names})"
