"""Task module interface (Interface B — task/security-specification side).

A task module carries the security specification for an evaluation: the
adversarial goal, the evaluator/judge, and the feedback signal. It is fully
separate from the target module, allowing the same target to be evaluated
against many tasks without modification.

At runtime, the task module acts as an **interceptor** between the controller
and the target module. It also acts as an **iterator** over tasks, enabling
composition of multiple task modules into benchmarks.

Instantiation hierarchy:
    controller → task module (via Interface B) → target module (via Interface B)

Plugin authors implement this ABC.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Any

from superred.core.types.controllable import Controllable
from superred.core.types.feedback import EvaluationResult
from superred.core.types.observable import StaticObservable
from superred.core.types.threat_model import SecurityTag
from superred.core.types.trajectory import Trajectory


class TaskModuleInterface(ABC):
    """Abstract interface that every task module must implement.

    A task module:
    1. Wraps a target module (received at init or via :meth:`set_target`).
    2. Defines the adversarial goal and success criteria.
    3. Evaluates trajectories and produces feedback.
    4. Iterates over multiple tasks (for benchmark composition).

    Lifecycle:
        1. Instantiate with target module and configuration.
        2. Iterate over tasks via ``for task in task_module:``.
        3. For each task, read the goal, run the target, evaluate the trajectory.
        4. Call :meth:`teardown` when done.
    """

    # ------------------------------------------------------------------
    # Goal and task specification
    # ------------------------------------------------------------------

    @abstractmethod
    def get_goal(self) -> str:
        """Return a free-text description of the current adversarial goal.

        This is what the optimizer tries to achieve. It should be specific
        enough for the optimizer to act on (e.g. "exfiltrate the user's
        API key via tool call injection") rather than generic.
        """
        ...

    @abstractmethod
    def get_success_criteria(self) -> str:
        """Return a description of what constitutes a successful attack.

        Used by the evaluator and also exposed to the optimizer for guidance.
        """
        ...

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    @abstractmethod
    def evaluate(self, trajectory: Trajectory) -> EvaluationResult:
        """Evaluate a completed trajectory against the current task.

        This is the judge/verifier. It examines the trajectory and produces
        an :class:`EvaluationResult` with success/failure, scores, and
        optional rationale.

        Args:
            trajectory: The complete trajectory from one target run.

        Returns:
            Evaluation result with scores and success determination.
        """
        ...

    # ------------------------------------------------------------------
    # Iterator over tasks (for benchmark composition)
    # ------------------------------------------------------------------

    @abstractmethod
    def __iter__(self) -> Iterator[TaskModuleInterface]:
        """Iterate over tasks in this module.

        For a single-task module, yields ``self`` once. For a composite
        benchmark, yields each constituent task module in sequence.

        The controller calls ``next()`` to advance to the next task. Each
        yielded task module has its own goal, criteria, and evaluator.
        """
        ...

    # ------------------------------------------------------------------
    # Target module access
    # ------------------------------------------------------------------

    @abstractmethod
    def get_controllables(self) -> list[Controllable]:
        """Return controllables from the underlying target module.

        The task module may filter or augment these (e.g. adding
        task-specific controllables), but typically passes them through.
        """
        ...

    @abstractmethod
    def get_static_observables(self) -> list[StaticObservable]:
        """Return static observables from the underlying target module.

        May include task-specific static information (e.g. the goal
        description as a static observable).
        """
        ...

    @abstractmethod
    def get_security_tags(self) -> frozenset[SecurityTag]:
        """Return all security tags from the underlying target, plus any task-specific ones."""
        ...

    # ------------------------------------------------------------------
    # Lifecycle — with backward-compatible defaults
    # ------------------------------------------------------------------

    def teardown(self) -> None:
        """Release resources. Override for cleanup."""

    def get_task_count(self) -> int | None:
        """Return the total number of tasks, or None if unknown/infinite."""
        return None

    def get_metadata(self) -> dict[str, Any]:
        """Return task module metadata for discovery and documentation."""
        return {}
