"""Feedback and evaluation types produced by task modules.

Feedback originates from the task module's evaluator and flows through the
controller to the optimizer. It includes a primary score for optimization
and optional sub-scores for multi-objective analysis (e.g. Pareto frontiers).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Score:
    """A single evaluation score.

    Attributes:
        value: Numeric score.  Meaning is relative / comparative only.
        name: Name of this score dimension (e.g. "asr", "utility_degradation").
        maximize: Whether higher values are better.
        metadata: Additional evaluator-specific metadata.
    """

    value: float
    name: str = "primary"
    maximize: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvaluationResult:
    """The result of evaluating a single run against a task.

    Attributes:
        success: Whether the adversarial goal was achieved (binary).
        primary_score: The main score used for optimization.
        sub_scores: Optional additional scores for multi-objective analysis.
        rationale: Optional free-text explanation from the evaluator.
        metadata: Additional evaluator-specific metadata.
    """

    success: bool
    primary_score: Score
    sub_scores: list[Score] = field(default_factory=list)
    rationale: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class FeedbackResult:
    """Complete feedback for one optimizer iteration.

    Bundles the evaluation result with the controllable values that produced
    it, giving the optimizer full context for its next step.
    """

    evaluation: EvaluationResult
    controllable_values_used: dict[str, Any] = field(default_factory=dict)
    run_id: str = ""
    iteration: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
