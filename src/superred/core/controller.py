"""Controller: the main orchestrator for red-teaming evaluations.

The controller sits between the target and optimizer, bridging
communication through an :class:`EventChannel`. It manages security
domain filtering, evaluation, and score tracking.

Usage::

    controller = Controller(
        optimizer=my_optimizer,
        target=my_target,
        security_claim=claim,
        security_domain_tag=external_tag,
        manual_values={"api_key": "sk-..."},
    )
    result = await controller.run()
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
from dataclasses import dataclass, field

from superred.core.interfaces.optimizer import Optimizer
from superred.core.interfaces.security_claim import SecurityClaim
from superred.core.interfaces.target import EventHandler, Target
from superred.core.interfaces.task import NotApplicable, Task
from superred.core.types.channel import EventChannel
from superred.core.types.evaluation import EvaluationResult, FeedbackResult, Score
from superred.core.types.event import (
    ControllablePostCallEvent,
    ControllablePreCallEvent,
    Event,
    EventResponse,
    NoModification,
    RunEndEvent,
    RunEndResponse,
    RunStartEvent,
)
from superred.core.types.security_domain import SecurityDomainTag
from superred.core.types.trajectory import FEEDBACK, Trajectory, TrajectoryEntry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RunResult:
    """Result of a single optimizer run (one target execution + evaluation).

    Attributes:
        trajectory: The run trajectory.
        evaluation: The evaluation result for this run.
    """

    trajectory: Trajectory
    evaluation: EvaluationResult


@dataclass(frozen=True)
class TaskResult:
    """Result of evaluating a single task across all optimizer runs.

    Attributes:
        task: The task that was evaluated.
        runs: All run results, in order.
        best_score: Highest primary score achieved across all runs.
        best_evaluation: The EvaluationResult that produced the best score.
        success: Whether any run achieved the adversarial goal.
    """

    task: Task[Target]
    runs: list[RunResult]
    best_score: Score
    best_evaluation: EvaluationResult
    success: bool


@dataclass(frozen=True)
class ControllerResult:
    """Result of a complete controller evaluation.

    Attributes:
        task_results: Results for each task in the security claim.
        skipped_tasks: Tasks that raised NotApplicable during configure.
    """

    task_results: list[TaskResult]
    skipped_tasks: list[Task[Target]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------


class Controller:
    """Orchestrates red-teaming evaluations.

    The controller is the main entry point. It:

    1. Validates manual specs and configures the target.
    2. Iterates tasks from the security claim.
    3. For each task, launches the optimizer as a concurrent actor and
       runs the target, bridging events through an :class:`EventChannel`
       with security domain filtering.
    4. Evaluates results and tracks scores.

    Args:
        optimizer: The optimizer (attacker) to use.
        target: The AI system under test.
        security_claim: The collection of tasks to evaluate.
        security_domain_tag: The security domain scope to test.
            Only controllables within this scope are forwarded to the optimizer.
        max_runs_per_task: Safety limit on runs per task.
    """

    def __init__(
        self,
        optimizer: Optimizer,
        target: Target,
        security_claim: SecurityClaim[Target],
        security_domain_tag: SecurityDomainTag,
        max_runs_per_task: int = 100,
    ) -> None:
        self._optimizer = optimizer
        self._target = target
        self._security_claim = security_claim
        self._security_domain_tag = security_domain_tag
        self._max_runs_per_task = max_runs_per_task

        self._event_log: list[tuple[Event, EventResponse]] = []
        self._event_log_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self) -> ControllerResult:
        """Run the full evaluation.

        Configures the target, iterates all tasks in the security claim,
        runs one optimizer pass per task, evaluates, and returns results.
        """
        task_results: list[TaskResult] = []
        skipped_tasks: list[Task[Target]] = []

        for task in self._security_claim:
            try:
                result = await self._run_task(task)
                task_results.append(result)
            except NotApplicable:
                skipped_tasks.append(task)
                logger.info(
                    "Task %r not applicable, skipping",
                    task.goal.description,
                )

        controller_result = ControllerResult(
            task_results=task_results,
            skipped_tasks=skipped_tasks,
        )

        self._print_summary(controller_result)

        await self._optimizer.teardown()
        await self._target.teardown()

        return controller_result

    # ------------------------------------------------------------------
    # Per-task run
    # ------------------------------------------------------------------

    async def _run_task(self, task: Task[Target]) -> TaskResult:
        """Run the optimizer loop for a single task.

        Runs iterations until the optimizer signals done or the safety
        limit is reached.
        """
        # Configure target (NotApplicable propagates to caller)
        await task.configure_target(self._target)

        # Initialize optimizer with this task's goal and surfaces
        controllables = self._target.get_controllables()
        observables = self._target.get_observables()
        await self._optimizer.initialize(task.goal, controllables, observables)

        # Create channel and launch optimizer as concurrent task
        channel = EventChannel()
        optimizer_task = asyncio.create_task(self._optimizer.run(channel))

        runs: list[RunResult] = []
        best_score: Score | None = None
        best_evaluation: EvaluationResult | None = None
        success = False

        try:
            for run_number in range(1, self._max_runs_per_task + 1):
                trajectory, evaluation, done = await self._run_single(
                    task, channel, run_number
                )
                runs.append(RunResult(trajectory=trajectory, evaluation=evaluation))

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
            # Shut down optimizer: close channel, wait for it to finish
            channel.close()
            with contextlib.suppress(asyncio.CancelledError):
                await optimizer_task

        assert best_score is not None
        assert best_evaluation is not None

        return TaskResult(
            task=task,
            runs=runs,
            best_score=best_score,
            best_evaluation=best_evaluation,
            success=success,
        )

    async def _run_single(
        self,
        task: Task[Target],
        channel: EventChannel,
        run_number: int,
    ) -> tuple[Trajectory, EvaluationResult, bool]:
        """Execute a single optimizer iteration (one target run + evaluation).

        Returns:
            A tuple of (trajectory, evaluation, done) where done is True
            if the optimizer wants to stop.
        """
        trajectory = Trajectory()

        # Signal run start
        await channel.send(RunStartEvent(trajectory=trajectory))

        # Run target — send_event bridges to channel with filtering
        await self._target.run(trajectory, self._make_send_event(channel))

        # Signal run end and check if optimizer wants to stop
        end_response = await channel.send(RunEndEvent(trajectory=trajectory))

        # Evaluate and append feedback
        evaluation = await task.evaluate(trajectory, self._target)
        feedback = FeedbackResult(evaluation=evaluation)
        trajectory.emit(TrajectoryEntry(entry_type=FEEDBACK, content=feedback))
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
    # Event bridging with security domain filtering
    # ------------------------------------------------------------------

    def _make_send_event(self, channel: EventChannel) -> EventHandler:
        """Create a send_event callback that bridges to the channel."""
        security_domain_tag = self._security_domain_tag

        async def send_event(event: Event) -> EventResponse:
            # Security domain filtering for controllable events
            if isinstance(event, (ControllablePreCallEvent, ControllablePostCallEvent)):
                controllable_domain = event.controllable.spec.security_domain
                if not security_domain_tag.includes(controllable_domain):
                    response: EventResponse = NoModification(event=event)
                    self._log_event(event, response)
                    return response

            # Forward through channel to optimizer
            response = await channel.send(event)
            self._log_event(event, response)
            return response

        return send_event

    def _log_event(self, event: Event, response: EventResponse) -> None:
        """Thread-safe event logging."""
        with self._event_log_lock:
            self._event_log.append((event, response))

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def event_log(self) -> list[tuple[Event, EventResponse]]:
        """All event-response pairs observed across all runs."""
        with self._event_log_lock:
            return list(self._event_log)

    # ------------------------------------------------------------------
    # CLI output
    # ------------------------------------------------------------------

    def _print_summary(self, result: ControllerResult) -> None:
        """Print a human-readable summary of the evaluation."""
        print("\n" + "=" * 60)
        print("Evaluation Summary")
        print("=" * 60)

        for tr in result.task_results:
            status = "SUCCEEDED" if tr.success else "FAILED"
            print(
                f"\n  [{status}] {tr.task.goal.description}"
                f"\n    Best score: {tr.best_score.value:.4f}"
                f"\n    Runs: {len(tr.runs)}"
            )

        if result.skipped_tasks:
            print(f"\n  Skipped: {len(result.skipped_tasks)} task(s) (NotApplicable)")

        if result.task_results:
            best = max(tr.best_score.value for tr in result.task_results)
            total_success = sum(1 for tr in result.task_results if tr.success)
            print(
                f"\n  Overall: {total_success}/{len(result.task_results)} tasks succeeded"
                f"\n  Highest score: {best:.4f}"
            )

        print("=" * 60 + "\n")
