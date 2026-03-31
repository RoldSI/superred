"""Abstract base class for evaluation tasks."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from superred.interfaces.target import Target
from superred.types import EvaluationResult, Goal, OracleBundle, Trajectory

T_Target = TypeVar("T_Target", bound=Target)


class NotApplicable(Exception):
    """Raised when a task is incompatible with a given target."""


class Task(ABC, Generic[T_Target]):
    """A concrete attack scenario or evaluation task.

    Each task defines a *goal*, knows how to *configure* a target for the
    scenario, and can *evaluate* whether the attack succeeded.
    """

    @property
    @abstractmethod
    def goal(self) -> Goal:
        """The goal the optimizer should try to achieve."""
        ...

    @abstractmethod
    async def configure(self, target: T_Target) -> dict[str, str]:
        """Prepare the target for this task. Returns config key-value pairs."""
        ...

    @abstractmethod
    async def evaluate(
        self, trajectory: Trajectory, target: T_Target
    ) -> EvaluationResult:
        """Score a trajectory against this task's success criteria."""
        ...

    @abstractmethod
    def oracle_bundle(self) -> OracleBundle:
        """Return oracle evidence the judge can use for evaluation."""
        ...
