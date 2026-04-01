"""Judge that searches trajectory content for a regex pattern."""

from __future__ import annotations

import re

from superred.interfaces.judge import Judge
from superred.types import EvaluationResult, Goal, OracleBundle, Score, Trajectory


class RegexJudge(Judge):
    """Succeeds when a regex pattern is (or is not) found in trajectory content."""

    def __init__(self, pattern: str, expect_match: bool = True) -> None:
        self._pattern = re.compile(pattern)
        self._expect_match = expect_match

    async def evaluate(
        self,
        goal: Goal,
        trajectory: Trajectory,
        oracle: OracleBundle,
    ) -> EvaluationResult:
        found = any(
            isinstance(e.content, str) and self._pattern.search(e.content)
            for e in trajectory.snapshot()
        )
        success = found == self._expect_match
        return EvaluationResult(
            success=success,
            primary_score=Score(value=1.0 if success else 0.0),
            rationale=f"Pattern {'found' if found else 'not found'}",
        )
