"""Judge that delegates evaluation to a user-supplied callable."""

from __future__ import annotations

from typing import Callable

from superred.interfaces.judge import Judge
from superred.types import EvaluationResult, Goal, OracleBundle, Score, Trajectory


class FunctionJudge(Judge):
    """Wraps a ``(Trajectory, OracleBundle) -> bool`` callable as a Judge."""

    def __init__(self, fn: Callable[[Trajectory, OracleBundle], bool]) -> None:
        self._fn = fn

    async def evaluate(
        self,
        goal: Goal,
        trajectory: Trajectory,
        oracle: OracleBundle,
    ) -> EvaluationResult:
        success = self._fn(trajectory, oracle)
        return EvaluationResult(
            success=success,
            primary_score=Score(value=1.0 if success else 0.0),
        )
