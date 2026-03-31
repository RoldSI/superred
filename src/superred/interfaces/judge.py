"""Abstract base class for judges (evaluation oracles)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from superred.types import EvaluationResult, Goal, OracleBundle, Trajectory


class Judge(ABC):
    """Scores a trajectory against a goal, optionally using oracle evidence."""

    @abstractmethod
    async def evaluate(
        self,
        goal: Goal,
        trajectory: Trajectory,
        oracle: OracleBundle,
    ) -> EvaluationResult:
        """Evaluate a trajectory and return a result with score."""
        ...
