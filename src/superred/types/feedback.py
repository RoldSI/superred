# src/superred/types/feedback.py
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass(frozen=True)
class Score:
    value: float
    name: str = "primary"

@dataclass(frozen=True)
class EvaluationResult:
    success: bool
    primary_score: Score
    sub_scores: dict[str, Score] = field(default_factory=dict)
    rationale: str = ""

@dataclass
class FeedbackResult:
    evaluation: EvaluationResult
