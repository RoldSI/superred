"""Optimizer module interface (Interface A / Interface C).

An optimizer module is an attacker abstracted as an optimization process. It
maximizes an adversarial outcome over a set of controllables, guided by
observables and feedback from the task evaluator.

Interface A: controller → optimizer (top-level).
Interface C: optimizer → sub-optimizer (same interface, enabling composition).

Optimizers form a tree/graph: a meta-optimizer can delegate to sub-optimizers,
each of which may further delegate. This enables modular composition of
attack strategies and interpretability of attack methodology.

At runtime, an optimizer runs **one iteration at a time** and may be
interrupted by its parent at any time. Only the top-level optimizer is
run until it signals exhaustion.

Plugin authors implement this ABC.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Any

from superred.core.types.budget import Budget, BudgetEstimate
from superred.core.types.controllable import Controllable, ControllableValue
from superred.core.types.feedback import FeedbackResult
from superred.core.types.observable import StaticObservable
from superred.core.types.trajectory import Trajectory


class OptimizerInterface(ABC):
    """Abstract interface that every optimizer module must implement.

    An optimizer:
    1. Receives controllables, observables, feedback, and budget from the
       controller (or parent optimizer).
    2. Produces controllable values for each iteration.
    3. Reports whether it has exhausted its search space.
    4. Provides cost estimates for budget planning.

    Lifecycle:
        1. Instantiate with configuration.
        2. Call :meth:`initialize` with goal, controllables, observables, budget.
        3. Loop: call :meth:`step` → get controllable values → run target →
           call :meth:`receive_feedback` → check :meth:`is_exhausted`.
        4. Call :meth:`teardown` when done.

    Sub-optimizer usage:
        An optimizer may import and instantiate other optimizers as sub-modules
        using this same interface. The parent allocates sub-budgets via
        :meth:`Budget.spawn_child` and delegates portions of the search space.
    """

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    @abstractmethod
    def initialize(
        self,
        goal: str,
        controllables: list[Controllable],
        static_observables: list[StaticObservable],
        budget: Budget | None = None,
    ) -> None:
        """Initialize the optimizer for a new optimization run.

        Called once before the iteration loop begins. The optimizer should
        store these for use in :meth:`step`.

        Args:
            goal: Free-text adversarial goal from the task module.
            controllables: Available attack surfaces (already filtered by
                threat model).
            static_observables: Static information about the target (already
                filtered by threat model).
            budget: Budget allocation for this optimizer. None means unlimited.
        """
        ...

    # ------------------------------------------------------------------
    # Iteration
    # ------------------------------------------------------------------

    @abstractmethod
    def step(
        self,
        trajectory: Trajectory | None = None,
        feedback: FeedbackResult | None = None,
    ) -> list[ControllableValue]:
        """Execute one optimization iteration and return controllable values.

        On the first call, ``trajectory`` and ``feedback`` are None.
        On subsequent calls, they contain the results from the previous run.

        The optimizer examines the trajectory (filtered by threat model) and
        feedback, updates its internal state, and produces new controllable
        values to try.

        Args:
            trajectory: Trajectory from the previous run (threat-model filtered),
                or None on first iteration.
            feedback: Evaluation feedback from the previous run, or None on
                first iteration.

        Returns:
            List of controllable values to inject in the next target run.
        """
        ...

    @abstractmethod
    def is_exhausted(self) -> bool:
        """Whether the optimizer has fully explored its search space.

        Returns True when the optimizer believes it has reached its best
        possible result and further iterations would not improve the outcome.
        The controller or parent optimizer uses this to decide when to stop.
        """
        ...

    # ------------------------------------------------------------------
    # Feedback
    # ------------------------------------------------------------------

    def receive_feedback(self, feedback: FeedbackResult) -> None:
        """Receive feedback outside the step loop.

        Optional hook for optimizers that want to process feedback separately
        from the step call (e.g. for async or event-driven architectures).
        Default: no-op (feedback is passed to :meth:`step` instead).
        """

    # ------------------------------------------------------------------
    # Budget estimation — v2 with backward-compatible defaults
    # ------------------------------------------------------------------

    def estimate_budget(self) -> BudgetEstimate:
        """Return a cost estimate for the remaining optimization.

        Estimates are propagated up the optimizer hierarchy to give the
        controller high-level cost projections. Updated after each iteration.

        Default: returns unknown estimate.
        """
        return BudgetEstimate.unknown()

    # ------------------------------------------------------------------
    # Sub-optimizer composition
    # ------------------------------------------------------------------

    def get_sub_optimizers(self) -> list[OptimizerInterface]:
        """Return sub-optimizers used by this optimizer, if any.

        Used for visualization (optimizer trees/graphs) and budget propagation.
        Default: empty list (leaf optimizer).
        """
        return []

    # ------------------------------------------------------------------
    # Iterator interface for streaming
    # ------------------------------------------------------------------

    def iterate(
        self,
        trajectory_stream: Iterator[Trajectory] | None = None,
    ) -> Iterator[list[ControllableValue]]:
        """Generator interface for the optimization loop.

        Alternative to the step-by-step API. Yields controllable values for
        each iteration. The caller sends trajectories and feedback via
        :meth:`step` / :meth:`receive_feedback`.

        Default implementation wraps :meth:`step` in a loop until exhausted.
        Override for custom iteration logic.
        """
        # First iteration: no trajectory or feedback
        yield self.step(trajectory=None, feedback=None)
        # Subsequent iterations driven by caller
        while not self.is_exhausted():
            # Caller is expected to call step() with trajectory/feedback
            # This default just yields empty to signal readiness
            yield []

    # ------------------------------------------------------------------
    # Lifecycle — with backward-compatible defaults
    # ------------------------------------------------------------------

    def teardown(self) -> None:
        """Release resources. Override for cleanup."""

    def get_metadata(self) -> dict[str, Any]:
        """Return optimizer metadata for discovery and documentation.

        Should include at minimum: name, description, and the types of
        controllables this optimizer can handle.
        """
        return {}

    def get_name(self) -> str:
        """Return a human-readable name for this optimizer.

        Default: class name.
        """
        return self.__class__.__name__
