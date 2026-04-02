"""Feedback and evaluation types produced by task modules.

Feedback originates from the task module's evaluator and flows through the
controller to the optimizer. It includes a primary score for optimization
and optional sub-scores for multi-objective analysis (e.g. Pareto frontiers).

Each :class:`Score` is tagged with a :class:`SecurityDomainTag`.  The
controller filters ``sub_scores`` by the active scope before writing
feedback to the trajectory, so the optimizer only sees scores within
its security domain.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from superred.core.types.security_domain import SecurityDomainTag


@dataclass(frozen=True)
class Score:
    """A single evaluation score.

    Attributes:
        value: Numeric score. Meaning is relative/comparative only. Higher values are better.
        name: Name of this score dimension (e.g. "asr", "utility_degradation").
        security_domain: The security domain this score pertains to.
    """

    value: float
    security_domain: SecurityDomainTag
    name: str = "primary"


@dataclass(frozen=True)
class EvaluationResult:
    """The result of evaluating a single run against a task.

    Attributes:
        success: Whether the adversarial goal was achieved (binary).
        primary_score: The main score used for optimization.
        sub_scores: Named sub-scores for multi-objective analysis, keyed by
            what each score evaluates (e.g. ``{"asr": Score(...), ...}``).
            Each score carries its own ``security_domain``.
        rationale: Optional free-text explanation from the evaluator.
    """

    success: bool
    primary_score: Score
    sub_scores: dict[str, Score] = field(default_factory=dict)
    rationale: str = ""


@dataclass
class FeedbackResult:
    """Content stored in FEEDBACK trajectory entries.

    Bundles the evaluation result for a specific scope, giving the
    optimizer context for its next step.

    Attributes:
        evaluation: The evaluation result from the task module.
    """

    evaluation: EvaluationResult
