"""Optimizer module interface (Interface C).

An optimizer module is an attacker abstracted as an optimisation process.  It
maximises an adversarial outcome over a set of controllables, guided by
observables and feedback from the task evaluator.

Interface A: controller -> optimizer (top-level).
Interface C: optimizer -> sub-optimizer (same interface, enabling composition).

Optimizers form a tree / graph: a meta-optimizer can delegate to
sub-optimizers, each of which may further delegate.  This enables modular
composition of attack strategies and interpretability of attack methodology.

At runtime, an optimizer runs **one iteration at a time** and may be
interrupted by its parent at any time.  Only the top-level optimizer is
run until it signals exhaustion.

Plugin authors implement classes conforming to :class:`OptimizerInterface`.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from superred.core.types.budget import BudgetEstimate, HierarchicalBudget
from superred.core.types.controllable import ControllableValue
from superred.core.types.feedback import FeedbackResult
from superred.core.types.observable import StaticObservable
from superred.core.types.threat_model import InterfaceSpec
from superred.core.types.trajectory import TraceEvent


@runtime_checkable
class OptimizerInterface(Protocol):
    """Abstract interface that every optimizer module must satisfy.

    An optimizer:
    1. Receives controllables, observables, feedback, and budget from the
       controller (or parent optimizer).
    2. Produces controllable values for each iteration.
    3. Reports whether it has exhausted its search space.
    4. Provides cost estimates for budget planning.

    Lifecycle:
        1. Instantiate with configuration.
        2. Call :meth:`initialize` with goal, controllables, observables, budget.
        3. Loop: call :meth:`step` -> get controllable values -> run target ->
           call :meth:`receive_feedback` -> check :meth:`is_exhausted`.
        4. Call :meth:`teardown` when done.
    """

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def initialize(
        self,
        goal: str,
        controllables: list[InterfaceSpec],
        static_observables: list[StaticObservable],
        budget: HierarchicalBudget | None = None,
    ) -> None:
        """Initialize the optimizer for a new optimisation run."""
        ...

    # ------------------------------------------------------------------
    # Iteration
    # ------------------------------------------------------------------

    def step(
        self,
        trace: Sequence[TraceEvent] | None = None,
        feedback: FeedbackResult | None = None,
    ) -> list[ControllableValue]:
        """Execute one optimisation iteration and return controllable values."""
        ...

    def is_exhausted(self) -> bool:
        """Whether the optimizer has fully explored its search space."""
        ...

    # ------------------------------------------------------------------
    # Feedback
    # ------------------------------------------------------------------

    def receive_feedback(self, feedback: FeedbackResult) -> None:
        """Receive feedback outside the step loop (optional hook)."""
        ...

    # ------------------------------------------------------------------
    # Budget estimation
    # ------------------------------------------------------------------

    def estimate_budget(self) -> BudgetEstimate:
        """Return a cost estimate for the remaining optimisation."""
        ...

    # ------------------------------------------------------------------
    # Sub-optimizer composition
    # ------------------------------------------------------------------

    def get_sub_optimizers(self) -> list[OptimizerInterface]:
        """Return sub-optimizers used by this optimizer, if any."""
        ...

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def teardown(self) -> None:
        """Release resources."""
        ...

    def get_metadata(self) -> dict[str, Any]:
        """Return optimizer metadata for discovery and documentation."""
        ...

    def get_name(self) -> str:
        """Return a human-readable name for this optimizer."""
        ...
