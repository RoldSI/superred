"""Controller: the main orchestrator for red-teaming evaluations.

The controller iterates **threat models** — combinations of a security
domain scope (:data:`Scope`) and an optional LLM configuration — and for
each threat model evaluates every task in the security claim.

All events, responses, and target entries are recorded on the
trajectory — the single source of truth for each run.

Usage::

    controller = Controller(
        optimizer_factory=lambda: MyOptimizer(),
        target=my_target,
        security_claim=claim,
        llm_configs=[my_llm_config],  # optional
    )
    result = await controller.run()
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from superred.core.channel import EventChannel
from superred.core.interfaces.optimizer import Optimizer
from superred.core.interfaces.security_claim import SecurityClaim
from superred.core.interfaces.target import Target
from superred.core.interfaces.task import NotApplicable, Task
from superred.core.llm import LLMClient
from superred.core.middleware import compose, security_domain_filter, trajectory_recorder
from superred.core.types.evaluation import EvaluationResult, Score
from superred.core.types.events import FeedbackEvent, RunEndEvent, RunEndResponse, RunStartEvent
from superred.core.types.llm import BudgetExhaustedError, LLMConfig, LLMUsage
from superred.core.types.security_domain import Scope, scope_includes
from superred.core.types.trajectory import Trajectory

logger = logging.getLogger(__name__)

# Type alias for optimizer factories.
OptimizerFactory = Callable[[], Optimizer]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RunResult:
    """Result of a single optimizer run (one target execution + evaluation).

    Attributes:
        trajectory: The run trajectory.
        evaluation: The evaluation result for this run.
        llm_usage: Cumulative optimizer LLM usage after this run.
    """

    trajectory: Trajectory
    evaluation: EvaluationResult
    llm_usage: LLMUsage


@dataclass(frozen=True)
class TaskResult:
    """Result of evaluating a single task across all optimizer runs.

    Attributes:
        task: The task that was evaluated.
        runs: All run results, in order.
        best_score: Highest primary score achieved across all runs.
        best_evaluation: The EvaluationResult that produced the best score.
        success: Whether any run achieved the adversarial goal.
        llm_usage: Total optimizer LLM usage across all runs.
    """

    task: Task[Target]
    runs: list[RunResult]
    best_score: Score
    best_evaluation: EvaluationResult
    success: bool
    llm_usage: LLMUsage


@dataclass(frozen=True)
class ThreatModelResult:
    """Results for a single threat model (scope + LLM config combination).

    Attributes:
        scope: The security domain scope tested.
        llm_config: The LLM configuration used, or ``None`` when no LLM
            configs were provided.
        task_results: Results for each evaluated task.
        skipped_tasks: Tasks that raised NotApplicable during configure.
    """

    scope: Scope
    llm_config: LLMConfig | None
    task_results: list[TaskResult]
    skipped_tasks: list[Task[Target]] = field(default_factory=list)


@dataclass(frozen=True)
class ControllerResult:
    """Result of a complete controller evaluation.

    Attributes:
        threat_model_results: Results for each threat model evaluated.
    """

    threat_model_results: list[ThreatModelResult]


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------


class Controller:
    """Orchestrates red-teaming evaluations across threat models.

    The controller iterates all relevant threat models — combinations of
    a security domain scope and an LLM configuration — and for each one
    evaluates every task in the security claim with a freshly instantiated
    optimizer.

    Args:
        optimizer_factory: A callable that returns a new :class:`Optimizer`
            instance.  A fresh optimizer is created for each
            (task, scope, llm_config) combination.
        target: The AI system under test.
        security_claim: The collection of tasks to evaluate.
        llm_configs: LLM access configurations for the optimizer.  Each
            config represents a different attacker model to test.  Optional
            — pass an empty list or omit for non-LLM optimizers.
        max_runs_per_task: Safety limit on runs per task.
    """

    def __init__(
        self,
        optimizer_factory: OptimizerFactory,
        target: Target,
        security_claim: SecurityClaim[Target],
        llm_configs: Sequence[LLMConfig] | None = None,
        max_runs_per_task: int = 100,
    ) -> None:
        if max_runs_per_task < 1:
            raise ValueError("max_runs_per_task must be at least 1")
        self._optimizer_factory = optimizer_factory
        self._target = target
        self._security_claim = security_claim
        self._llm_configs: list[LLMConfig] = list(llm_configs) if llm_configs else []
        self._max_runs_per_task = max_runs_per_task

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        *,
        scopes: Sequence[Scope] | None = None,
        models: Sequence[str] | None = None,
    ) -> ControllerResult:
        """Run the full evaluation across threat models.

        Args:
            scopes: Security domain scopes to test.  Each scope is a
                ``frozenset[SecurityDomainTag]``.  If ``None``, uses all
                non-empty combinations from the target's
                :meth:`~SecurityDomain.distinct_combinations`.
            models: Model names to test (must match an ``LLMConfig.model``
                in *llm_configs*).  If ``None``, uses all configured
                ``llm_configs``.  Ignored when ``llm_configs`` is empty.

        Returns:
            A :class:`ControllerResult` with results for each threat model.
        """
        # Resolve scopes
        effective_scopes = self._resolve_scopes(scopes)

        # Resolve LLM configs
        effective_configs = self._resolve_llm_configs(models)

        try:
            results = await self._iterate_threat_models(
                effective_scopes, effective_configs,
            )
        finally:
            await self._target.teardown()

        controller_result = ControllerResult(threat_model_results=results)
        self._print_summary(controller_result)
        return controller_result

    # ------------------------------------------------------------------
    # Resolution helpers
    # ------------------------------------------------------------------

    def _resolve_scopes(
        self, scopes: Sequence[Scope] | None,
    ) -> list[Scope]:
        """Resolve scopes to test."""
        if scopes is not None:
            return list(scopes)
        # Default: all non-empty combinations from the target's domain
        all_combos = self._target.security_domain.distinct_combinations()
        return [c for c in all_combos if c]

    def _resolve_llm_configs(
        self, models: Sequence[str] | None,
    ) -> list[LLMConfig]:
        """Resolve LLM configs to test."""
        if not self._llm_configs:
            return []
        if models is None:
            return list(self._llm_configs)
        model_set = set(models)
        return [c for c in self._llm_configs if c.model in model_set]

    # ------------------------------------------------------------------
    # Threat model iteration
    # ------------------------------------------------------------------

    async def _iterate_threat_models(
        self,
        scopes: list[Scope],
        llm_configs: list[LLMConfig],
    ) -> list[ThreatModelResult]:
        """Iterate all (scope, llm_config) combinations."""
        results: list[ThreatModelResult] = []

        if llm_configs:
            for scope in scopes:
                for llm_config in llm_configs:
                    result = await self._iterate_tasks(scope, llm_config)
                    results.append(result)
        else:
            # No LLM configs — iterate scopes only
            for scope in scopes:
                result = await self._iterate_tasks(scope, None)
                results.append(result)

        return results

    # ------------------------------------------------------------------
    # Task iteration (one threat model)
    # ------------------------------------------------------------------

    async def _iterate_tasks(
        self,
        scope: Scope,
        llm_config: LLMConfig | None,
    ) -> ThreatModelResult:
        """Iterate all tasks for a single threat model."""
        task_results: list[TaskResult] = []
        skipped_tasks: list[Task[Target]] = []

        for task in self._security_claim:
            try:
                result = await self._run_task(task, scope, llm_config)
                task_results.append(result)
            except NotApplicable:
                skipped_tasks.append(task)
                logger.info(
                    "Task %r not applicable, skipping",
                    task.goal.description,
                )

        return ThreatModelResult(
            scope=scope,
            llm_config=llm_config,
            task_results=task_results,
            skipped_tasks=skipped_tasks,
        )

    # ------------------------------------------------------------------
    # Per-task run
    # ------------------------------------------------------------------

    async def _run_task(
        self,
        task: Task[Target],
        scope: Scope,
        llm_config: LLMConfig | None,
    ) -> TaskResult:
        """Run the optimizer loop for a single task + threat model.

        A fresh optimizer and :class:`LLMClient` are created for each call.
        """
        # Configure target (NotApplicable propagates to caller)
        await task.configure_target(self._target)

        # Create a fresh LLM client if we have a config
        llm_client: LLMClient | None = LLMClient(llm_config) if llm_config else None

        # Fresh optimizer for this (task, scope, llm_config) combo
        optimizer = self._optimizer_factory()

        # Initialize optimizer with filtered surfaces (only in-scope items)
        controllables = [
            c for c in self._target.get_controllables()
            if scope_includes(scope, c.security_domain)
        ]
        observables = [
            o for o in self._target.get_observables()
            if scope_includes(scope, o.observable.security_domain)
        ]
        await optimizer.initialize(
            task.goal, controllables, observables,
            llm_client if llm_client is not None else LLMClient._make_noop(),
        )

        # Create channel and launch optimizer as concurrent task.
        channel = EventChannel()

        async def _optimizer_with_error_propagation() -> None:
            try:
                await optimizer.run(channel)
            except Exception as exc:
                channel.set_error(exc)
                raise

        optimizer_task = asyncio.create_task(_optimizer_with_error_propagation())

        runs: list[RunResult] = []
        best_score: Score | None = None
        best_evaluation: EvaluationResult | None = None
        success = False

        try:
            for run_number in range(1, self._max_runs_per_task + 1):
                try:
                    trajectory, evaluation, done = await self._run_single(
                        task, channel, scope, run_number,
                    )
                except BudgetExhaustedError:
                    logger.info(
                        "Task %r: LLM budget exhausted during run %d, stopping task",
                        task.goal.description,
                        run_number,
                    )
                    break

                run_usage = llm_client.usage if llm_client else LLMUsage()
                runs.append(RunResult(
                    trajectory=trajectory, evaluation=evaluation, llm_usage=run_usage,
                ))

                # Track best score
                if best_score is None or evaluation.primary_score.value > best_score.value:
                    best_score = evaluation.primary_score
                    best_evaluation = evaluation
                if evaluation.success:
                    success = True

                # Cleanup target state for next run
                await self._target.cleanup()

                if done:
                    break

        finally:
            channel.close()
            try:
                await optimizer_task
            except Exception:
                pass
            await optimizer.teardown()

        # If budget exhausted before the first run completed, synthesize
        # a zero-score result so the task still appears in results.
        if best_score is None:
            best_score = Score(value=0.0, name="primary")
            best_evaluation = EvaluationResult(
                success=False,
                primary_score=best_score,
                sub_scores={},
                rationale="LLM budget exhausted before first run completed.",
            )
        assert best_evaluation is not None

        task_usage = llm_client.usage if llm_client else LLMUsage()
        return TaskResult(
            task=task,
            runs=runs,
            best_score=best_score,
            best_evaluation=best_evaluation,
            success=success,
            llm_usage=task_usage,
        )

    async def _run_single(
        self,
        task: Task[Target],
        channel: EventChannel,
        scope: Scope,
        run_number: int,
    ) -> tuple[Trajectory, EvaluationResult, bool]:
        """Execute a single optimizer iteration (one target run + evaluation).

        Returns:
            A tuple of (trajectory, evaluation, done) where done is True
            if the optimizer wants to stop.
        """
        trajectory = Trajectory(filtered_scope=scope)

        # Signal run start — optimizer gets filtered view
        await channel.send(RunStartEvent(trajectory=trajectory.filtered))

        # Build the event pipeline: record → filter → send to optimizer
        send_event = compose(
            trajectory_recorder(trajectory),
            security_domain_filter(scope),
        )(channel.send)

        # Target runs — events go through the pipeline
        await self._target.run(trajectory.emit, send_event)

        # Signal run end — optimizer gets filtered view
        end_response = await channel.send(RunEndEvent(trajectory=trajectory.filtered))

        # -- Evaluate --
        evaluation = await task.evaluate(trajectory, self._target)

        # Filter sub_scores to only include in-scope scores, then append
        # feedback to trajectory.  primary_score, success, and rationale
        # are always included (the optimizer needs the main signal).
        #
        # FeedbackEvent requires a security_domain (single tag).  Use
        # an arbitrary tag from the scope; if the scope is empty the
        # feedback cannot be emitted (empty scope = nothing in scope).
        filtered_sub = {
            k: v for k, v in evaluation.sub_scores.items()
            if v.security_domain is None or scope_includes(scope, v.security_domain)
        }
        filtered_eval = EvaluationResult(
            success=evaluation.success,
            primary_score=evaluation.primary_score,
            sub_scores=filtered_sub,
            rationale=evaluation.rationale,
        )
        # Pick a representative tag for the FeedbackEvent's security_domain.
        # Any tag in the scope works — all are in scope by definition.
        feedback_tag = next(iter(scope)) if scope else None
        trajectory.emit(FeedbackEvent(
            evaluation=filtered_eval,
            security_domain=feedback_tag,
        ))
        trajectory.close()

        done = isinstance(end_response, RunEndResponse) and end_response.done

        logger.info(
            "Task %r run %d: score=%.4f success=%s done=%s",
            task.goal.description,
            run_number,
            evaluation.primary_score.value,
            evaluation.success,
            done,
        )

        return trajectory, evaluation, done

    # ------------------------------------------------------------------
    # CLI output
    # ------------------------------------------------------------------

    def _print_summary(self, result: ControllerResult) -> None:
        """Print a human-readable summary of the evaluation."""
        print("\n" + "=" * 60)
        print("Evaluation Summary")
        print("=" * 60)

        for tmr in result.threat_model_results:
            scope_names = ", ".join(sorted(t.name for t in tmr.scope)) or "(empty)"
            model_name = tmr.llm_config.model if tmr.llm_config else "(no LLM)"
            print(f"\n  Threat model: scope=[{scope_names}] model={model_name}")

            for tr in tmr.task_results:
                status = "SUCCEEDED" if tr.success else "FAILED"
                print(
                    f"\n    [{status}] {tr.task.goal.description}"
                    f"\n      Best score: {tr.best_score.value:.4f}"
                    f"\n      Runs: {len(tr.runs)}"
                    f"\n      LLM usage: {tr.llm_usage.calls} calls,"
                    f" ${tr.llm_usage.cost:.6f}"
                )

            if tmr.skipped_tasks:
                print(
                    f"\n    Skipped: {len(tmr.skipped_tasks)} task(s) (NotApplicable)"
                )

        all_task_results = [
            tr
            for tmr in result.threat_model_results
            for tr in tmr.task_results
        ]
        if all_task_results:
            best = max(tr.best_score.value for tr in all_task_results)
            total_success = sum(1 for tr in all_task_results if tr.success)
            print(
                f"\n  Overall: {total_success}/{len(all_task_results)} task evaluations"
                f" succeeded\n  Highest score: {best:.4f}"
            )

        print("=" * 60 + "\n")
