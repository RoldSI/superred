"""Judge that delegates evaluation to an LLM-style callable with retries."""

from __future__ import annotations

from typing import Callable

from superred.interfaces.judge import Judge
from superred.types import EvaluationResult, Goal, OracleBundle, Score, Trajectory


class LLMJudge(Judge):
    """Placeholder LLM judge that wraps a ``(goal, content) -> (bool, float)`` callable.

    In production this would call an actual LLM for evaluation.  The callable
    receives the goal description and the concatenated trajectory content and
    returns a ``(success, score)`` tuple.
    """

    def __init__(
        self,
        judge_fn: Callable[[str, str], tuple[bool, float]],
        max_retries: int = 3,
    ) -> None:
        self._judge_fn = judge_fn
        self._max_retries = max_retries

    async def evaluate(
        self,
        goal: Goal,
        trajectory: Trajectory,
        oracle: OracleBundle,
    ) -> EvaluationResult:
        content = "\n".join(str(e.content) for e in trajectory.snapshot())
        for attempt in range(self._max_retries):
            try:
                success, score = self._judge_fn(goal.description, content)
                return EvaluationResult(
                    success=success,
                    primary_score=Score(value=score),
                )
            except Exception:
                if attempt == self._max_retries - 1:
                    return EvaluationResult(
                        success=False,
                        primary_score=Score(value=0.0),
                        rationale="Judge evaluation failed after retries",
                    )
        # Unreachable, but keeps the type checker happy.
        raise RuntimeError("Unreachable")  # pragma: no cover
