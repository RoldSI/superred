"""Controller: orchestrates one red-teaming threat model.

One ``Controller`` instance evaluates one security claim against one
``(scope, llm_config)`` threat model.  Each task in the claim runs
against a fresh :class:`Target` from the configured
:class:`TargetFactory`; tasks run concurrently up to
``target_factory.concurrency`` at a time, with each task's events,
responses, and trajectory entries recorded on its own trajectory — the
single source of truth per run.

To sweep multiple scopes or attacker models, instantiate one
``Controller`` per threat model at the experiment level and run them
sequentially or via ``asyncio.gather``.

Usage::

    target_factory = TargetFactory(
        create=lambda: MyTarget(...),
        concurrency=8,
    )
    controller = Controller(
        optimizer_factory=lambda: MyOptimizer(),
        target_factory=target_factory,
        security_claim=claim,
        scope=my_scope,
        llm_config=my_llm_config,  # or omit for non-LLM optimizers
    )
    result = await controller.run()  # -> ThreatModelResult
"""

from __future__ import annotations

import asyncio
import logging
import traceback
from collections.abc import Awaitable, Callable
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
from superred.core.persistence import (
    prepare_results_dir,
    task_detail_filename,
    write_claim_summary,
    write_task_detail,
)
from superred.core.types.controllable import Controllable
from superred.core.types.evaluation import EvaluationResult, Score
from superred.core.types.events import RunEndEvent, RunEndResponse, RunStartEvent
from superred.core.types.llm import BudgetExhaustedError, LLMConfig, LLMUsage
from superred.core.types.observable import Observable, ObservableValue
from superred.core.types.security_domain import Scope, scope_includes
from superred.core.types.trajectory import Trajectory

logger = logging.getLogger(__name__)

# Type alias for optimizer factories.
OptimizerFactory = Callable[[], Optimizer]

# Reason a task's run loop ended.
StopReason = Literal["done", "max_runs", "budget_exhausted", "error"]


# ---------------------------------------------------------------------------
# Target factory
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TargetFactory:
    """Produces fresh :class:`Target` instances and declares parallel capacity.

    The controller calls :attr:`create` once per task and runs up to
    :attr:`concurrency` tasks in parallel within a threat model.  Each
    task owns its target's full lifecycle: ``configure_target`` →
    ``run``/``reset_ephemeral_state`` loop → ``teardown``.

    Attributes:
        create: Zero-arg callable that returns a new :class:`Target`.
            The controller calls this once per task; the instance is
            discarded after ``teardown``.
        concurrency: Maximum tasks that may run in parallel against
            independent target instances from this factory.  Defaults to
            ``1`` (sequential).  Target authors choose this based on
            external rate limits or resource cost — a cheap, stateless
            target (a chatbot wrapping an API) can comfortably use ``8``
            or more; a target that boots a sandbox should usually stay
            at ``1`` unless it pools internally.
    """

    create: Callable[[], Target]
    concurrency: int = 1

    def __post_init__(self) -> None:
        if self.concurrency < 1:
            raise ValueError("TargetFactory.concurrency must be at least 1")

    @classmethod
    def singleton(cls, target: Target) -> TargetFactory:
        """Wrap a single target instance so the factory always returns it.

        Concurrency is locked to ``1`` because a shared instance cannot
        safely serve parallel tasks — mutable target state would race.

        Intended for tests and small migrations.  Note that the controller
        still calls ``target.teardown()`` once per task in the security
        claim, so a singleton-wrapped target needs an idempotent
        ``teardown()`` (or a no-op one) if the claim has more than one
        task.  For real targets that hold expensive resources, prefer a
        non-singleton factory whose ``create()`` returns a fresh instance
        each call.
        """
        return cls(create=lambda: target, concurrency=1)


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
        runs: All run results, in order.  When the task ended with
            ``stop_reason="error"`` due to a failure inside a run, the
            run-in-progress is appended with the partial trajectory it
            had accumulated and a zero-score :class:`EvaluationResult`.
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
            task was abandoned.
        error: Formatted exception (type + message + traceback) when the
            task ended with ``stop_reason="error"``; ``None`` otherwise.
            Lands in the persisted JSON for offline debugging.
    """

    task: Task[Target]
    runs: list[RunResult]
    best_score: Score
    best_evaluation: EvaluationResult
    success: bool
    llm_usage: LLMUsage
    stop_reason: StopReason
    error: str | None = None


@dataclass(frozen=True)
class ThreatModelResult:
    """Results for a single threat model (scope + LLM config combination).

    Attributes:
        scope: The read & write scope tested (visible and injectable).
        read_only: Extra visible-but-not-injectable tags (empty for an
            all-read & write run).
        llm_config: The LLM configuration used, or ``None`` when no LLM
            configs were provided.
        task_results: Results for each evaluated task.
        skipped_tasks: Tasks that raised NotApplicable during configure.
    """

    scope: Scope
    read_only: Scope
    llm_config: LLMConfig | None
    task_results: list[TaskResult]
    skipped_tasks: list[Task[Target]] = field(default_factory=list)


def _format_exception(exc: BaseException) -> str:
    """Format an exception with type, message, and traceback for the JSON log."""
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def _controllable_as_observable(controllable: Controllable) -> ObservableValue:
    """Re-present a read-only controllable as an observable for the optimizer.

    When a controllable's tag is visible but not in the write scope, the
    optimizer can read the surface but never inject into it — so for this
    threat model it is an observable, not a controllable.  Surfacing it in
    the ``observables`` list (rather than ``controllables``) keeps the
    optimizer's view honest: ``controllables`` means "injectable".

    ``content`` is ``None`` because the value is not known statically; it is
    revealed at runtime on the trajectory via the controllable's (declined)
    events.  The name and security domain are preserved so the optimizer can
    still identify the surface.
    """
    return ObservableValue(
        observable=Observable(
            name=controllable.name,
            security_domain=controllable.security_domain,
            description=controllable.description,
            observable_type=controllable.value_type,
        ),
        content=None,
    )


def _synthesize_empty_task_result(
    task: Task[Target],
    *,
    stop_reason: StopReason,
    rationale: str,
    usage: LLMUsage = LLMUsage(),
    exc: BaseException | None = None,
) -> TaskResult:
    """Build a zero-score TaskResult for a task whose run loop never produced a run.

    Used by the error and budget-exhausted paths that abandon a task before
    any run completes. When *exc* is provided its formatted traceback is
    stored on ``TaskResult.error`` so the failure is recoverable from the
    persisted detail file.
    """
    zero = Score(value=0.0, name="primary")
    return TaskResult(
        task=task,
        runs=[],
        best_score=zero,
        best_evaluation=EvaluationResult(
            success=False,
            primary_score=zero,
            sub_scores={},
            rationale=rationale,
        ),
        success=False,
        llm_usage=usage,
        stop_reason=stop_reason,
        error=_format_exception(exc) if exc is not None else None,
    )


async def _swallow(coro: Awaitable[None], description: str) -> None:
    """Await *coro*, logging and swallowing any Exception.

    Used in error paths and ``finally`` blocks where a failing cleanup
    must not mask an in-flight exception or block the next task.
    """
    try:
        await coro
    except Exception:
        logger.exception("%s failed", description)


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------


class Controller:
    """Orchestrates one threat model: a single security claim evaluated
    against a single ``(scope, llm_config)`` combination.

    One ``Controller`` instance is one threat model.  To sweep multiple
    scopes or attacker models, construct one ``Controller`` per
    combination at the experiment level and ``asyncio.gather`` them (or
    iterate sequentially).

    Within the threat model, tasks run concurrently up to
    ``target_factory.concurrency`` at a time.  Each task owns its
    target's full lifecycle so concurrent tasks never share mutable
    target state.

    Args:
        optimizer_factory: A callable that returns a new :class:`Optimizer`
            instance.  A fresh optimizer is created for each task.
        target_factory: Produces fresh :class:`Target` instances and
            declares how many tasks may run in parallel against
            independent instances (see :class:`TargetFactory`).
        security_claim: The collection of tasks to evaluate.
        scope: The read & write security domain scope: the
            ``frozenset[SecurityDomainTag]`` the attacker can both *see*
            and *inject* into.  Controllables, observables, trajectory
            entries, and feedback sub-scores under these tags (and their
            descendants) are exposed to the optimizer, and its
            controllable events are offered for injection.
        read_only: Extra tags the attacker can *see* but not inject into.
            Empty (default) means the whole ``scope`` is read & write
            (the classic behavior).  Tags here (and their descendants)
            are visible on every surface — trajectory, observables,
            feedback — but their controllable events are answered with
            ``ControllableNoInjection`` without consulting the optimizer.
            Put a read & write tag in ``scope`` and a visible-only
            ancestor in ``read_only`` to make just that subtree
            injectable (e.g. ``scope={system_prompt}, read_only={system}``).
            A ``read_only`` tag already covered by ``scope`` has no effect:
            read & write overrules (only ``scope`` drives the injection
            decision), so the tag stays injectable.  ``scope`` and
            ``read_only`` cannot both be empty.
        llm_config: LLM access configuration for the optimizer, or
            ``None`` for non-LLM optimizers (in which case the optimizer
            receives a noop client that raises on any call).
        max_runs_per_task: Safety limit on runs per task. ``None`` (default)
            uses the built-in cap of 100; pass an explicit positive int to
            override.
        results_dir: Optional directory for persisted artifacts. When set,
            the completed threat model is written atomically to
            ``{results_dir}/{scope}__{model}.json`` (plus a sibling
            subfolder with per-task detail files) when ``run()`` finishes.
            ``LLMConfig.api_key`` and ``api_base`` are excluded;
            trajectory contents are not scrubbed for secrets.
    """

    DEFAULT_MAX_RUNS_PER_TASK = 100

    def __init__(
        self,
        optimizer_factory: OptimizerFactory,
        target_factory: TargetFactory,
        security_claim: SecurityClaim[Target],
        scope: Scope,
        read_only: Scope = frozenset(),
        llm_config: LLMConfig | None = None,
        max_runs_per_task: int | None = None,
        include_feedback: bool = True,
        results_dir: str | Path | None = None,
    ) -> None:
        # ``scope`` is the read & write surface (visible AND injectable);
        # ``read_only`` adds tags that are visible but not injectable.
        # By default ``read_only`` is empty, so the whole scope is
        # read & write (the classic behavior).
        self._write_scope: Scope = scope  # injectable
        self._read_only: Scope = read_only  # visible but not injectable
        self._visibility: Scope = scope | read_only  # everything the optimizer sees
        if not self._visibility:
            raise ValueError("scope and read_only cannot both be empty")
        resolved_max_runs = (
            self.DEFAULT_MAX_RUNS_PER_TASK if max_runs_per_task is None else max_runs_per_task
        )
        if resolved_max_runs < 1:
            raise ValueError("max_runs_per_task must be at least 1")
        self._optimizer_factory = optimizer_factory
        self._target_factory = target_factory
        self._security_claim = security_claim
        self._llm_config: LLMConfig | None = llm_config
        self._max_runs_per_task = resolved_max_runs
        self._include_feedback = include_feedback
        self._results_dir: Path | None = Path(results_dir) if results_dir is not None else None

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self) -> ThreatModelResult:
        """Evaluate the security claim under this controller's threat model.

        Returns:
            A :class:`ThreatModelResult` for the configured
            ``(scope, llm_config)``.  When ``results_dir`` is set,
            per-task detail files are written incrementally as each
            task completes, and the claim-level summary lands at the
            end as a completion marker.
        """
        result, task_file_basenames = await self._iterate_tasks()
        if self._results_dir is not None:
            write_claim_summary(self._results_dir, result, task_file_basenames)
        self._print_summary(result)
        return result

    # ------------------------------------------------------------------
    # Task iteration (one threat model)
    # ------------------------------------------------------------------

    async def _iterate_tasks(self) -> tuple[ThreatModelResult, list[str]]:
        """Iterate all tasks for a single threat model.

        Tasks run concurrently bounded by ``target_factory.concurrency``.
        Each in-flight task owns a fresh :class:`Target` produced by the
        factory; the controller never shares a target across concurrent
        tasks.  Results are collected in input order so the per-threat-
        model output is deterministic across re-runs (modulo timing
        non-determinism inside individual tasks).

        Per-task error containment: errors raised during a task's run loop
        are caught inside ``_run_task`` and reflected via
        ``stop_reason="error"`` on the returned :class:`TaskResult`. Errors
        raised *outside* the run loop — inside ``target_factory.create()``,
        ``task.configure_target``, or ``optimizer.initialize`` — are caught
        here as a backstop, recorded as a synthetic error
        :class:`TaskResult`, and do not abort the threat model.

        Incremental persistence: when ``results_dir`` is set, each
        task's detail file is written as soon as its
        :class:`TaskResult` is built — so an aborted run still leaves
        every completed task on disk.  Returns the per-task file
        basenames in the same order as ``task_results`` so the caller
        can stitch them into the claim-level summary.
        """
        sem = asyncio.Semaphore(self._target_factory.concurrency)

        subfolder: Path | None = None
        if self._results_dir is not None:
            # Up-front so FileExistsError fires before any task runs.
            subfolder = prepare_results_dir(
                self._results_dir, self._write_scope, self._read_only, self._llm_config
            )

        async def run_one(
            index: int,
            task: Task[Target],
        ) -> tuple[TaskResult | Task[Target], str | None]:
            """Return ``(outcome, detail_basename)``.

            *outcome* is a ``TaskResult`` when the task ran (success or
            error) or the ``Task`` itself when it raised
            ``NotApplicable``.  *detail_basename* is the filename of the
            per-task JSON written into *subfolder* (``None`` when
            persistence is disabled or the task was skipped).
            """
            async with sem:
                # ``factory.create()`` may itself raise (e.g. a target whose
                # __init__ does network setup).  Contain it here so one
                # bad task can't take down the rest of the threat model
                # via ``asyncio.gather``'s first-exception behavior.
                outcome: TaskResult | Task[Target]
                try:
                    target = self._target_factory.create()
                except Exception as exc:
                    logger.exception(
                        "Task %r: target_factory.create() failed, recording as error",
                        task.goal.description,
                    )
                    outcome = _synthesize_empty_task_result(
                        task,
                        stop_reason="error",
                        rationale="Unexpected error before run loop started.",
                        exc=exc,
                    )
                else:
                    try:
                        try:
                            outcome = await self._run_task(task, target)
                        except NotApplicable:
                            logger.info(
                                "Task %r not applicable, skipping",
                                task.goal.description,
                            )
                            outcome = task
                        except Exception as exc:
                            logger.exception(
                                "Task %r: unexpected error before run loop, recording as error",
                                task.goal.description,
                            )
                            outcome = _synthesize_empty_task_result(
                                task,
                                stop_reason="error",
                                rationale="Unexpected error before run loop started.",
                                exc=exc,
                            )
                    finally:
                        # Released before the next task's semaphore slot opens.
                        await _swallow(target.teardown(), "target.teardown post-task")

                # Incremental write. Basename is computed up front so the
                # summary can record the intended path even if the write
                # itself raises; skipped tasks have no detail file.
                detail_basename: str | None = None
                if subfolder is not None and isinstance(outcome, TaskResult):
                    detail_basename = task_detail_filename(index, outcome.task.goal.description)
                    try:
                        write_task_detail(
                            subfolder,
                            detail_basename,
                            outcome,
                            self._write_scope,
                            self._read_only,
                            self._llm_config,
                        )
                    except Exception:
                        logger.exception(
                            "Task %r: failed to write per-task detail file (continuing)",
                            task.goal.description,
                        )
                return outcome, detail_basename

        outcomes = await asyncio.gather(
            *(run_one(i, t) for i, t in enumerate(self._security_claim, start=1)),
        )

        task_results: list[TaskResult] = []
        skipped_tasks: list[Task[Target]] = []
        task_file_basenames: list[str] = []
        for outcome, basename in outcomes:
            if isinstance(outcome, TaskResult):
                task_results.append(outcome)
                if subfolder is not None:
                    # run_one always sets basename when persistence is on
                    # (computed before the write attempt).
                    assert basename is not None
                    task_file_basenames.append(basename)
            else:
                skipped_tasks.append(outcome)

        result = ThreatModelResult(
            scope=self._write_scope,
            read_only=self._read_only,
            llm_config=self._llm_config,
            task_results=task_results,
            skipped_tasks=skipped_tasks,
        )
        return result, task_file_basenames

    # ------------------------------------------------------------------
    # Per-task run
    # ------------------------------------------------------------------

    async def _run_task(
        self,
        task: Task[Target],
        target: Target,
    ) -> TaskResult:
        """Run the optimizer loop for a single task.

        A fresh optimizer and :class:`LLMClient` are created for each call;
        the caller (``_iterate_tasks``) supplies a fresh target and owns
        its teardown after this returns.  Scope and LLM config are read
        from ``self`` (constant for the threat model).
        """
        # Configure target (NotApplicable propagates to caller)
        await task.configure_target(target)

        # Create a fresh LLM client if we have a config
        llm_client: LLMClient | None = LLMClient(self._llm_config) if self._llm_config else None

        # Fresh optimizer for this task
        optimizer = self._optimizer_factory()

        # Split the target's controllables by access level.  The optimizer
        # only gets the injectable ones in ``controllables``; a controllable
        # that is visible but not writable (read-only this run) is surfaced
        # in ``observables`` instead, so the list it can inject into is honest.
        all_controllables = target.get_controllables()
        controllables = [
            c for c in all_controllables if scope_includes(self._write_scope, c.security_domain)
        ]
        # Readable surfaces: in-visibility observables, plus read-only
        # controllables re-presented as observables.
        observables = [
            o
            for o in target.get_observables()
            if scope_includes(self._visibility, o.observable.security_domain)
        ]
        observables += [
            _controllable_as_observable(c)
            for c in all_controllables
            if scope_includes(self._visibility, c.security_domain)
            and not scope_includes(self._write_scope, c.security_domain)
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
            # warmup call). Return a budget_exhausted result directly so it
            # isn't misclassified as a generic error by _iterate_tasks.
            await _swallow(optimizer.teardown(), "optimizer.teardown after init-budget-exhausted")
            logger.info(
                "Task %r: LLM budget exhausted during optimizer.initialize, stopping task",
                task.goal.description,
            )
            return _synthesize_empty_task_result(
                task,
                stop_reason="budget_exhausted",
                rationale="LLM budget exhausted before first run completed.",
                usage=llm_client.usage if llm_client else LLMUsage(),
            )
        except Exception:
            # Tear down before re-raising so the optimizer doesn't leak;
            # _iterate_tasks catches and records the error.
            await _swallow(optimizer.teardown(), "optimizer.teardown after init-error")
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
        error_text: str | None = None

        try:
            for run_number in range(1, self._max_runs_per_task + 1):
                # Trajectory is owned by _run_task (not _run_single) so the
                # partial trajectory survives any exception inside the run.
                trajectory = Trajectory(filtered_scope=self._visibility)
                try:
                    evaluation, done = await self._run_single(
                        task,
                        target,
                        channel,
                        run_number,
                        trajectory,
                    )
                except BudgetExhaustedError:
                    logger.info(
                        "Task %r: LLM budget exhausted during run %d, stopping task",
                        task.goal.description,
                        run_number,
                    )
                    stop_reason = "budget_exhausted"
                    break
                except Exception as exc:
                    # _run_single failed mid-run — preserve the partial
                    # trajectory it accumulated, attach a zero-score
                    # evaluation, and store the formatted exception on
                    # ``TaskResult.error`` so the failure is recoverable
                    # from the persisted JSON.
                    logger.exception(
                        "Task %r: unexpected error during run %d, stopping task",
                        task.goal.description,
                        run_number,
                    )
                    error_text = _format_exception(exc)
                    error_eval = EvaluationResult(
                        success=False,
                        primary_score=Score(value=0.0, name="primary"),
                        sub_scores={},
                        rationale=f"Run {run_number} failed: {type(exc).__name__}: {exc}",
                    )
                    run_usage = llm_client.usage if llm_client else LLMUsage()
                    runs.append(
                        RunResult(
                            trajectory=trajectory,
                            evaluation=error_eval,
                            llm_usage=run_usage,
                        )
                    )
                    stop_reason = "error"
                    break

                # _run_single succeeded — record the run.
                run_usage = llm_client.usage if llm_client else LLMUsage()
                runs.append(
                    RunResult(
                        trajectory=trajectory,
                        evaluation=evaluation,
                        llm_usage=run_usage,
                    )
                )
                if best_score is None or evaluation.primary_score.value > best_score.value:
                    best_score = evaluation.primary_score
                    best_evaluation = evaluation
                if evaluation.success:
                    success = True

                # Reset ephemeral target state for next run within this task.  If
                # reset_ephemeral_state raises, the successful run we just appended stays
                # — only the task is abandoned, with the reset exception
                # captured on ``error``.
                try:
                    await target.reset_ephemeral_state()
                except Exception as exc:
                    logger.exception(
                        "Task %r: target.reset_ephemeral_state() failed after run %d, "
                        "stopping task",
                        task.goal.description,
                        run_number,
                    )
                    error_text = _format_exception(exc)
                    stop_reason = "error"
                    break

                if done:
                    stop_reason = "done"
                    break

        finally:
            channel.close()
            try:
                await optimizer_task
            except Exception as exc:
                # Optimizer raised outside any in-flight channel.send
                # (background work, or its own teardown after the run loop
                # exited). Captured as a diagnostic without changing
                # stop_reason — the run loop's classification is authoritative.
                logger.exception(
                    "Task %r: optimizer task raised during teardown",
                    task.goal.description,
                )
                if error_text is None:
                    error_text = _format_exception(exc)
            await _swallow(optimizer.teardown(), "optimizer.teardown post-run")
            # Final reset_ephemeral_state so the target ends in a reset state even when the
            # inner-loop reset-after-success was skipped. Target teardown
            # itself happens in the caller before the next semaphore slot opens.
            await _swallow(target.reset_ephemeral_state(), "target.reset_ephemeral_state post-task")

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
            error=error_text,
        )

    async def _run_single(
        self,
        task: Task[Target],
        target: Target,
        channel: EventChannel,
        run_number: int,
        trajectory: Trajectory,
    ) -> tuple[EvaluationResult, bool]:
        """Execute a single optimizer iteration (one target run + evaluation).

        Order: target.run → evaluate → RunEndEvent (persisted) → close.
        The optimizer reads the evaluation from RunEndEvent.evaluation
        (when ``include_feedback=True``) or from the trajectory.

        The trajectory is constructed by the caller (``_run_task``) so that
        a failure mid-run still leaves a partial trajectory accessible for
        persistence and debugging.

        Returns:
            A tuple of (evaluation, done) where done is True if the
            optimizer wants to stop.
        """
        assert self._visibility, "scope must contain at least one tag"

        # Signal run start — optimizer gets filtered view
        await channel.send(RunStartEvent(trajectory=trajectory.filtered))

        # Build the event pipeline: record → filter → send to optimizer.
        # The filter gets the read & write scope: controllable events under
        # read-only tags (outside it) are declined with
        # ControllableNoInjection without consulting the optimizer, but the
        # recorder (outermost) still records them — being in the full
        # visibility scope, they stay visible through the optimizer's
        # filtered trajectory view.
        send_event = compose(
            trajectory_recorder(trajectory),
            security_domain_filter(self._write_scope),
        )(channel.send)

        # Target runs — events go through the pipeline
        await target.run(trajectory.emit, send_event)

        # -- Evaluate --
        evaluation = await task.evaluate(trajectory, target)

        # Filter sub_scores to only include in-scope scores.
        # primary_score, success, and rationale are always included
        # (the optimizer needs the main signal).
        filtered_sub = {
            k: v
            for k, v in evaluation.sub_scores.items()
            if v.security_domain is None or scope_includes(self._visibility, v.security_domain)
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
            security_domain=next(iter(self._visibility)),
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

        return evaluation, done

    # ------------------------------------------------------------------
    # CLI output
    # ------------------------------------------------------------------

    def _print_summary(self, tmr: ThreatModelResult) -> None:
        """Print a human-readable summary of one threat model."""
        scope_names = ", ".join(sorted(t.name for t in tmr.scope)) or "(none)"
        if tmr.read_only:
            ro_names = ", ".join(sorted(t.name for t in tmr.read_only))
            access = f" read_only=[{ro_names}]"
        else:
            access = ""
        model_name = tmr.llm_config.model if tmr.llm_config else "(no LLM)"
        print("\n" + "=" * 60)
        print(f"Threat model: scope=[{scope_names}]{access} model={model_name}")
        print("=" * 60)

        for tr in tmr.task_results:
            status = "SUCCEEDED" if tr.success else "FAILED"
            print(
                f"\n  [{status}] {tr.task.goal.description}"
                f"\n    Best score: {tr.best_score.value:.4f}"
                f"\n    Runs: {len(tr.runs)}"
                f"\n    LLM usage: {tr.llm_usage.calls} calls,"
                f" ${tr.llm_usage.cost:.6f}"
            )

        if tmr.skipped_tasks:
            print(f"\n  Skipped: {len(tmr.skipped_tasks)} task(s) (NotApplicable)")

        if tmr.task_results:
            best = max(tr.best_score.value for tr in tmr.task_results)
            total_success = sum(1 for tr in tmr.task_results if tr.success)
            print(
                f"\n  Overall: {total_success}/{len(tmr.task_results)} tasks succeeded"
                f"\n  Highest score: {best:.4f}"
            )

        print("=" * 60 + "\n")
