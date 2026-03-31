"""Result types for evaluation runs, tasks, and overall evaluations."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from superred.types import Trajectory, EvaluationResult, Goal
from superred.types.security import ThreatModel
from superred.types.budget import BudgetUsage
from superred.types.claim import ClaimVerdict


@dataclass
class RunResult:
    """Outcome of a single optimizer run against a target."""

    trajectory: Trajectory
    evaluation: EvaluationResult
    claim_verdicts: list[ClaimVerdict] = field(default_factory=list)
    budget_used: BudgetUsage = field(default_factory=BudgetUsage)
    threat_model: ThreatModel | None = None
    optimizer_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskResult:
    """Aggregated results for a single task goal across multiple runs."""

    task_goal: Goal
    runs: list[RunResult] = field(default_factory=list)

    @property
    def best_run(self) -> RunResult | None:
        """Return the run with the highest primary score, or None if no runs."""
        if not self.runs:
            return None
        return max(self.runs, key=lambda r: r.evaluation.primary_score.value)


@dataclass
class EvalResult:
    """Top-level evaluation result, keyed by threat-model name."""

    task_results: dict[str, list[TaskResult]] = field(default_factory=dict)

    def asr_by_threat_model(self) -> dict[str, float]:
        """Compute attack success rate for each threat model."""
        result = {}
        for tm_name, task_results in self.task_results.items():
            total = sum(len(tr.runs) for tr in task_results)
            successes = sum(
                sum(1 for r in tr.runs if r.evaluation.success)
                for tr in task_results
            )
            result[tm_name] = successes / total if total > 0 else 0.0
        return result
