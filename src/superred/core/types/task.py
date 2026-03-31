"""Task definition and feedback types.

A task module carries the security specification for a given evaluation:
the goal, the evaluator / judge, and the feedback signal.  These types
capture the task's identity and the evaluation output independently of
any specific target system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

from superred.core.types.security_claims import ClaimVerdict


@dataclass(frozen=True)
class TaskDefinition:
    """Identity and goal description for a single evaluation task."""

    task_id: str
    name: str
    description: str
    benign_goal: Optional[str] = None
    adversarial_goal: Optional[str] = None


@dataclass(frozen=True)
class TaskFeedback:
    """Feedback produced by the task evaluator after a run."""

    score: float
    subscores: Mapping[str, float]
    verdicts: Sequence[ClaimVerdict]
    metadata: Mapping[str, Any] = field(default_factory=dict)
