"""The Controller is the central orchestrator.

It:
    1. Takes a target module + task module + optimizer module + threat models
    2. Binds the task module to the target (bound = task.bind(target))
    3. For each threat model: opens a run session, drives the optimisation loop
    4. Produces a comprehensive EvalResult
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Sequence

from superred.core.interfaces.optimizer import OptimizerInterface
from superred.core.interfaces.target import TargetModuleInterface
from superred.core.interfaces.task import (
    BoundTaskTargetInterface,
    EvaluatedRunInterface,
    TaskModuleInterface,
)
from superred.core.types.budget import BudgetUsage, HierarchicalBudget
from superred.core.types.controllable import ControllableValue
from superred.core.types.feedback import EvaluationResult, FeedbackResult, Score
from superred.core.types.task import TaskDefinition, TaskFeedback
from superred.core.types.threat_model import Budget, InterfaceSpec, ThreatModel
from superred.core.types.trajectory import TraceEvent

logger = logging.getLogger("superred.controller")


@dataclass
class RunResult:
    """Result of one optimiser run on one task under one threat model."""

    task_id: str
    threat_model_name: str
    optimizer_name: str
    success: bool
    best_score: float
    iterations_used: int
    budget_used: BudgetUsage
    best_controllables: dict[str, Any]
    trace: Sequence[TraceEvent]
    feedback: Optional[TaskFeedback]
    wall_clock_seconds: float
    history: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class TaskResult:
    """Aggregated results for one task across all threat models."""

    task_id: str
    runs: list[RunResult] = field(default_factory=list)

    @property
    def asr_by_threat_model(self) -> dict[str, float]:
        return {run.threat_model_name: (1.0 if run.success else 0.0) for run in self.runs}


@dataclass
class EvalResult:
    """Complete evaluation result across all tasks and threat models."""

    target_id: str
    optimizer_name: str
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: Optional[datetime] = None
    task_results: list[TaskResult] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        threat_models: set[str] = set()
        for tr in self.task_results:
            for run in tr.runs:
                threat_models.add(run.threat_model_name)

        out: dict[str, Any] = {}
        for tm in sorted(threat_models):
            runs = [
                r for tr in self.task_results for r in tr.runs if r.threat_model_name == tm
            ]
            total = len(runs)
            successes = sum(1 for r in runs if r.success)
            avg_score = sum(r.best_score for r in runs) / max(1, total)
            avg_iters = sum(r.iterations_used for r in runs) / max(1, total)
            avg_cost = sum(r.budget_used.cost_usd for r in runs) / max(1, total)

            out[tm] = {
                "asr": successes / max(1, total),
                "total_tasks": total,
                "successes": successes,
                "avg_score": avg_score,
                "avg_iterations": avg_iters,
                "avg_cost_usd": avg_cost,
            }
        return out

    def to_json(self) -> str:
        return json.dumps(self.summary(), indent=2)


class Controller:
    """Main orchestrator for the framework.

    Usage::

        controller = Controller()
        result = controller.run(
            target=my_target,
            task=my_task,
            optimizer=my_optimizer,
            threat_models=[tm1, tm2, tm3],
        )
        print(result.summary())
    """

    def __init__(self, verbose: bool = True):
        self.verbose = verbose

    def run(
        self,
        target: TargetModuleInterface,
        task: TaskModuleInterface,
        optimizer: OptimizerInterface,
        threat_models: list[ThreatModel],
        runtime_params: Mapping[str, Any] | None = None,
        budget: Budget | None = None,
    ) -> EvalResult:
        """Run the full evaluation.

        For each threat model:
            1. Bind the task module to the target
            2. Open a run session with the bound composite
            3. Drive the optimisation loop via the optimizer
            4. Record results
        """
        runtime_params = runtime_params or {}
        budget = budget or Budget(max_iterations=20)
        bound = task.bind(target)
        task_def = bound.task_definition()
        meta = bound.metadata()

        eval_result = EvalResult(
            target_id=meta.target_id,
            optimizer_name=optimizer.get_name(),
        )

        total_runs = len(threat_models)
        for idx, tm in enumerate(threat_models, 1):
            if self.verbose:
                logger.info(
                    "[%d/%d] Task: %s, Threat Model: C=%d O=%d F=%d",
                    idx,
                    total_runs,
                    task_def.task_id,
                    len(tm.allowed_controllables),
                    len(tm.allowed_observables),
                    len(tm.allowed_feedback),
                )

            run_result = self._run_single(
                bound=bound,
                optimizer=optimizer,
                threat_model=tm,
                task_def=task_def,
                runtime_params=runtime_params,
                budget=budget,
            )

            task_result = TaskResult(task_id=task_def.task_id, runs=[run_result])
            eval_result.task_results.append(task_result)

            if self.verbose:
                logger.info(
                    "  Result: success=%s, score=%.3f, iters=%d, time=%.1fs",
                    run_result.success,
                    run_result.best_score,
                    run_result.iterations_used,
                    run_result.wall_clock_seconds,
                )

        eval_result.finished_at = datetime.now(timezone.utc)
        return eval_result

    def _run_single(
        self,
        bound: BoundTaskTargetInterface,
        optimizer: OptimizerInterface,
        threat_model: ThreatModel,
        task_def: TaskDefinition,
        runtime_params: Mapping[str, Any],
        budget: Budget,
    ) -> RunResult:
        """Run one optimiser on one task under one threat model."""
        run = bound.open_run(threat_model=threat_model, runtime_params=runtime_params)

        controllable_specs = list(run.available_controllables())
        static_obs: list[Any] = []
        h_budget = HierarchicalBudget(
            max_iterations=budget.max_iterations or 0,
            max_input_tokens=budget.max_input_tokens or 0,
            max_output_tokens=budget.max_output_tokens or 0,
            max_cost_usd=budget.max_cost_usd or 0.0,
            max_wall_clock_seconds=budget.max_wall_clock_seconds or 0.0,
        )

        goal = task_def.adversarial_goal or task_def.description
        optimizer.initialize(goal, controllable_specs, static_obs, h_budget)

        start_time = time.time()
        budget_used = BudgetUsage()
        best_score = 0.0
        best_controllables: dict[str, Any] = {}
        last_feedback: Optional[TaskFeedback] = None
        history: list[dict[str, Any]] = []
        iteration = 0

        while True:
            iteration += 1
            if h_budget.is_exhausted:
                break

            ctrl_values = optimizer.step(
                trace=list(run.trace()) if iteration > 1 else None,
                feedback=_task_feedback_to_result(last_feedback) if last_feedback else None,
            )

            values_map: dict[str, Any] = {}
            for cv in ctrl_values:
                values_map[cv.name] = cv.value
            run.apply_controllables(values_map)

            turn = run.step()

            last_feedback = run.latest_feedback()
            budget_used.iterations += 1
            budget_used.wall_clock_seconds = time.time() - start_time
            h_budget.record_usage(BudgetUsage(iterations=1))

            score = last_feedback.score if last_feedback else 0.0
            success = score >= 1.0

            history.append({
                "iteration": iteration,
                "success": success,
                "score": score,
                "controllables": values_map,
            })

            if score > best_score:
                best_score = score
                best_controllables = values_map

            if success or turn.done:
                break
            if optimizer.is_exhausted():
                break

        trace = list(run.trace())
        run.close()

        return RunResult(
            task_id=task_def.task_id,
            threat_model_name=f"C{len(threat_model.allowed_controllables)}_O{len(threat_model.allowed_observables)}",
            optimizer_name=optimizer.get_name(),
            success=best_score >= 1.0,
            best_score=best_score,
            iterations_used=iteration,
            budget_used=budget_used,
            best_controllables=best_controllables,
            trace=trace,
            feedback=last_feedback,
            wall_clock_seconds=time.time() - start_time,
            history=history,
        )


def _task_feedback_to_result(fb: TaskFeedback) -> FeedbackResult:
    """Bridge TaskFeedback into FeedbackResult for the optimiser."""
    return FeedbackResult(
        evaluation=EvaluationResult(
            success=fb.score >= 1.0,
            primary_score=Score(value=fb.score),
            sub_scores=[Score(value=v, name=k) for k, v in fb.subscores.items()],
        ),
    )
