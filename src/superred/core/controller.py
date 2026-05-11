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
from pathlib import Path
from typing import Literal

from superred.core.channel import EventChannel
from superred.core.interfaces.optimizer import Optimizer
from superred.core.interfaces.security_claim import SecurityClaim
from superred.core.interfaces.target import Target
from superred.core.interfaces.task import NotApplicable, Task
from superred.core.llm import LLMClient
from superred.core.middleware import compose, security_domain_filter, trajectory_recorder
from superred.core.persistence import write_threat_model_result
from superred.core.types.evaluation import EvaluationResult, Score
from superred.core.types.events import RunEndEvent, RunEndResponse, RunStartEvent
from superred.core.types.llm import BudgetExhaustedError, LLMConfig, LLMUsage
from superred.core.types.security_domain import Scope, scope_includes
from superred.core.types.trajectory import Trajectory

logger = logging.getLogger(__name__)

# Type alias for optimizer factories.
OptimizerFactory = Callable[[], Optimizer]

# Reason a task's run loop ended.
StopReason = Literal["done", "max_runs", "budget_exhausted", "error"]


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
        stop_reason: Why the run loop ended.  ``"done"`` means the optimizer
            returned ``RunEndResponse(done=True)``.  ``"max_runs"`` means
            the safety cap ``max_runs_per_task`` was reached.
            ``"budget_exhausted"`` means a :class:`BudgetExhaustedError`
            was raised by the LLM client.  ``"error"`` means an unexpected
            exception escaped the optimizer, target, or evaluator and the
            task was abandoned; any runs already completed before the
            failure are preserved in ``runs``.
    """

    task: Task[Target]
    runs: list[RunResult]
    best_score: Score
    best_evaluation: EvaluationResult
    success: bool
    llm_usage: LLMUsage
    stop_reason: StopReason


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


def _synthesize_error_task_result(task: Task[Target]) -> TaskResult:
    """Build a placeholder TaskResult for a task that failed before its run loop."""
    zero = Score(value=0.0, name="primary")
    return TaskResult(
        task=task,
        runs=[],
        best_score=zero,
        best_evaluation=EvaluationResult(
            success=False,
            primary_score=zero,
            sub_scores={},
            rationale="Unexpected error before run loop started.",
        ),
        success=False,
        llm_usage=LLMUsage(),
        stop_reason="error",
    )


def _synthesize_budget_exhausted_task_result(
    task: Task[Target], usage: LLMUsage,
) -> TaskResult:
    """Build a placeholder TaskResult for a task whose optimizer ran out of
    LLM budget before any run completed (e.g. inside ``optimizer.initialize``)."""
    zero = Score(value=0.0, name="primary")
    return TaskResult(
        task=task,
        runs=[],
        best_score=zero,
        best_evaluation=EvaluationResult(
            success=False,
            primary_score=zero,
            sub_scores={},
            rationale="LLM budget exhausted before first run completed.",
        ),
        success=False,
        llm_usage=usage,
        stop_reason="budget_exhausted",
    )


async def _safe_teardown(optimizer: Optimizer, context: str) -> None:
    """Call ``optimizer.teardown()`` swallowing and logging any exception.

    Used in error-handling paths where a failing teardown must not mask
    the original exception (or, in the ``finally`` block, must not
    propagate over an exception that is already in flight).
    """
    try:
        await optimizer.teardown()
    except Exception:
        logger.exception("optimizer.teardown failed during %s", context)


async def _safe_cleanup(target: Target, context: str) -> None:
    """Call ``target.cleanup()`` swallowing and logging any exception.

    Used in the post-task ``finally`` block so a failing task always
    leaves the target in a reset state for the next task, even when
    the inner-loop cleanup-after-success was skipped due to an error.
    """
    try:
        await target.cleanup()
    except Exception:
        logger.exception("target.cleanup failed during %s", context)


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
        results_dir: Optional directory for persisted artifacts. When set,
            each completed threat model is written atomically to
            ``{results_dir}/{scope}__{model}.json`` immediately after it
            finishes — so a later threat model that crashes does not lose
            already-completed ones. Trajectories, evaluations, and
            cumulative LLM usage per run are included; ``LLMConfig.api_key``
            and ``api_base`` are not. Trajectory contents are not scrubbed
            for secrets.
    """

    def __init__(
        self,
        optimizer_factory: OptimizerFactory,
        target: Target,
        security_claim: SecurityClaim[Target],
        llm_configs: Sequence[LLMConfig] | None = None,
        max_runs_per_task: int = 100,
        include_feedback: bool = True,
        results_dir: str | Path | None = None,
    ) -> None:
        if max_runs_per_task < 1:
            raise ValueError("max_runs_per_task must be at least 1")
        self._optimizer_factory = optimizer_factory
        self._target = target
        self._security_claim = security_claim
        self._llm_configs: list[LLMConfig] = list(llm_configs) if llm_configs else []
        self._max_runs_per_task = max_runs_per_task
        self._include_feedback = include_feedback
        self._results_dir: Path | None = Path(results_dir) if results_dir is not None else None

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
                effective_scopes,
                effective_configs,
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
        self,
        scopes: Sequence[Scope] | None,
    ) -> list[Scope]:
        """Resolve scopes to test.

        Every scope must be non-empty — an empty scope covers nothing
        and cannot provide a security domain for trajectory events.

        Raises:
            ValueError: If any scope is empty.
        """
        if scopes is not None:
            resolved = list(scopes)
        else:
            # Default: all non-empty combinations from the target's domain
            all_combos = self._target.security_domain.distinct_combinations()
            resolved = [c for c in all_combos if c]
        for s in resolved:
            if not s:
                raise ValueError("Scope must not be empty")
        return resolved

    def _resolve_llm_configs(
        self,
        models: Sequence[str] | None,
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
        """Iterate all (scope, llm_config) combinations.

        After each completed threat model, the result is persisted to
        ``self._results_dir`` (when configured) before the next one
        begins. This keeps already-finished threat models safe if a
        later iteration raises.
        """
        results: list[ThreatModelResult] = []
        config_axis: list[LLMConfig | None] = list(llm_configs) if llm_configs else [None]

        for scope in scopes:
            for llm_config in config_axis:
                result = await self._iterate_tasks(scope, llm_config)
                results.append(result)
                if self._results_dir is not None:
                    write_threat_model_result(result, self._results_dir)

        return results

    # ------------------------------------------------------------------
    # Task iteration (one threat model)
    # ------------------------------------------------------------------

    async def _iterate_tasks(
        self,
        scope: Scope,
        llm_config: LLMConfig | None,
    ) -> ThreatModelResult:
        """Iterate all tasks for a single threat model.

        Per-task error containment: errors raised during a task's run loop
        are caught inside ``_run_task`` and reflected via
        ``stop_reason="error"`` on the returned :class:`TaskResult`. Errors
        raised *outside* the run loop (e.g. inside ``configure_target`` or
        ``optimizer.initialize``) are caught here as a backstop, recorded
        as a synthetic error :class:`TaskResult`, and do not abort the
        threat model.
        """
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
            except Exception:
                logger.exception(
                    "Task %r: unexpected error before run loop, recording as error",
                    task.goal.description,
                )
                task_results.append(_synthesize_error_task_result(task))

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
            c for c in self._target.get_controllables() if scope_includes(scope, c.security_domain)
        ]
        observables = [
            o
            for o in self._target.get_observables()
            if scope_includes(scope, o.observable.security_domain)
        ]
        try:
            await optimizer.initialize(
                task.goal,
                controllables,
                observables,
                llm_client if llm_client is not None else LLMClient._make_noop(),
            )
        except BudgetExhaustedError:
            # Optimizer exhausted its LLM budget inside initialize (e.g. a
            # warmup call). Tear down and return a budget_exhausted result
            # directly so it isn't misclassified as a generic error by
            # _iterate_tasks.
            await _safe_teardown(optimizer, "init budget-exhausted cleanup")
            logger.info(
                "Task %r: LLM budget exhausted during optimizer.initialize, stopping task",
                task.goal.description,
            )
            return _synthesize_budget_exhausted_task_result(
                task,
                llm_client.usage if llm_client else LLMUsage(),
            )
        except Exception:
            # Initialize failed: tear down before re-raising so the optimizer
            # doesn't leak. _iterate_tasks catches and records the error.
            # _safe_teardown ensures a failing teardown does not mask the
            # initialize exception we're about to re-raise.
            await _safe_teardown(optimizer, "init error cleanup")
            raise

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
        # Default reason: if the for-loop exits without an explicit break,
        # the safety cap was reached.
        stop_reason: StopReason = "max_runs"

        try:
            for run_number in range(1, self._max_runs_per_task + 1):
                try:
                    trajectory, evaluation, done = await self._run_single(
                        task,
                        channel,
                        scope,
                        run_number,
                    )

                    run_usage = llm_client.usage if llm_client else LLMUsage()
                    runs.append(
                        RunResult(
                            trajectory=trajectory,
                            evaluation=evaluation,
                            llm_usage=run_usage,
                        )
                    )

                    # Track best score
                    if best_score is None or evaluation.primary_score.value > best_score.value:
                        best_score = evaluation.primary_score
                        best_evaluation = evaluation
                    if evaluation.success:
                        success = True

                    # Cleanup target state for next run
                    await self._target.cleanup()

                    if done:
                        stop_reason = "done"
                        break
                except BudgetExhaustedError:
                    logger.info(
                        "Task %r: LLM budget exhausted during run %d, stopping task",
                        task.goal.description,
                        run_number,
                    )
                    stop_reason = "budget_exhausted"
                    break
                except Exception:
                    # Any other exception escaping the optimizer, target, or
                    # evaluator stops just this task — the threat model is
                    # still persisted with the surviving tasks. Runs already
                    # appended above are preserved.
                    logger.exception(
                        "Task %r: unexpected error during run %d, stopping task",
                        task.goal.description,
                        run_number,
                    )
                    stop_reason = "error"
                    break

        finally:
            channel.close()
            try:
                await optimizer_task
            except Exception:
                pass
            # _safe_teardown so a failing teardown in the finally path
            # cannot propagate over an exception already in flight from
            # the try-body.
            await _safe_teardown(optimizer, "post-run cleanup")
            # Final target.cleanup so the next task starts against a clean
            # target even if the inner-loop cleanup-after-success was
            # skipped due to an error. Wrapped because cleanup itself may
            # fail (e.g. cascading from the same fault that broke the run);
            # we log and continue rather than mask the in-flight exception
            # or block the next task.
            await _safe_cleanup(self._target, "post-task cleanup")

        # If the loop ended before any run completed (budget exhausted or
        # error on run 1), synthesize a zero-score result so the task still
        # appears in results.
        if best_score is None:
            best_score = Score(value=0.0, name="primary")
            if stop_reason == "error":
                rationale = "Unexpected error before first run completed."
            else:
                rationale = "LLM budget exhausted before first run completed."
            best_evaluation = EvaluationResult(
                success=False,
                primary_score=best_score,
                sub_scores={},
                rationale=rationale,
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
            stop_reason=stop_reason,
        )

    async def _run_single(
        self,
        task: Task[Target],
        channel: EventChannel,
        scope: Scope,
        run_number: int,
    ) -> tuple[Trajectory, EvaluationResult, bool]:
        """Execute a single optimizer iteration (one target run + evaluation).

        Order: target.run → evaluate → RunEndEvent (persisted) → close.
        The optimizer reads the evaluation from RunEndEvent.evaluation
        (when ``include_feedback=True``) or from the trajectory.

        Returns:
            A tuple of (trajectory, evaluation, done) where done is True
            if the optimizer wants to stop.
        """
        assert scope, "scope must contain at least one tag"

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

        # -- Evaluate --
        evaluation = await task.evaluate(trajectory, self._target)

        # Filter sub_scores to only include in-scope scores.
        # primary_score, success, and rationale are always included
        # (the optimizer needs the main signal).
        filtered_sub = {
            k: v
            for k, v in evaluation.sub_scores.items()
            if v.security_domain is None or scope_includes(scope, v.security_domain)
        }
        filtered_eval = EvaluationResult(
            success=evaluation.success,
            primary_score=evaluation.primary_score,
            sub_scores=filtered_sub,
            rationale=evaluation.rationale,
        )

        # RunEndEvent is persisted to the trajectory.
        # include_feedback controls whether evaluation data is attached.
        run_end_eval = filtered_eval if self._include_feedback else None
        run_end = RunEndEvent(
            evaluation=run_end_eval,
            security_domain=next(iter(scope)),
        )
        trajectory.emit(run_end)
        end_response = await channel.send(run_end)

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
                print(f"\n    Skipped: {len(tmr.skipped_tasks)} task(s) (NotApplicable)")

        all_task_results = [tr for tmr in result.threat_model_results for tr in tmr.task_results]
        if all_task_results:
            best = max(tr.best_score.value for tr in all_task_results)
            total_success = sum(1 for tr in all_task_results if tr.success)
            print(
                f"\n  Overall: {total_success}/{len(all_task_results)} task evaluations"
                f" succeeded\n  Highest score: {best:.4f}"
            )

        print("=" * 60 + "\n")
