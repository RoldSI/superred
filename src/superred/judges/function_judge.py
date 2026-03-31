"""Programmatic ground-truth judge using callable functions."""

from __future__ import annotations

from typing import Any, Callable, Sequence

from superred.core.types.feedback import EvaluationResult, Score
from superred.core.types.trajectory import TraceEvent

GroundTruthFn = Callable[[Sequence[TraceEvent]], bool]
ScoreFn = Callable[[Sequence[TraceEvent]], float]


class FunctionJudge:
    """Evaluates attack success using a programmatic ground-truth function.

    Wraps arbitrary Python callables as judge functions.
    Useful for benchmarks with deterministic evaluation criteria.
    """

    def __init__(
        self,
        success_fn: GroundTruthFn,
        score_fn: ScoreFn | None = None,
        utility_fn: GroundTruthFn | None = None,
    ):
        self._success_fn = success_fn
        self._score_fn = score_fn
        self._utility_fn = utility_fn

    def evaluate(self, trace: Sequence[TraceEvent]) -> EvaluationResult:
        success = self._success_fn(trace)
        score = self._score_fn(trace) if self._score_fn else (1.0 if success else 0.0)
        utility = self._utility_fn(trace) if self._utility_fn else True

        return EvaluationResult(
            success=success,
            primary_score=Score(value=score, name="attack_success"),
            sub_scores=[Score(value=1.0 if utility else 0.0, name="utility")],
        )


def make_keyword_judge(
    success_keywords: list[str],
    failure_keywords: list[str] | None = None,
) -> FunctionJudge:
    """Create a simple keyword-matching judge."""

    def success_fn(trace: Sequence[TraceEvent]) -> bool:
        text = " ".join(str(e.payload) for e in trace).lower()
        if failure_keywords:
            for kw in failure_keywords:
                if kw.lower() in text:
                    return False
        return any(kw.lower() in text for kw in success_keywords)

    return FunctionJudge(success_fn=success_fn)
