"""Tests for the Controller orchestrator."""

from __future__ import annotations

import pytest

from superred.core.controller import Controller, ControllerResult
from superred.core.interfaces.security_claim import SecurityClaim
from superred.core.types.evaluation import EvaluationResult, Score
from superred.core.types.event import (
    ControllableInjection,
    ControllablePreCallEvent,
    NoModification,
    RunEndEvent,
    RunStartEvent,
)
from superred.core.types.trajectory import FEEDBACK, MODEL_REQUEST, Trajectory, TrajectoryEntry

from .conftest import (
    EXTERNAL_TAG,
    INTERNAL_TAG,
    ROOT_TAG,
    CountingOptimizer,
    FailingOnEventOptimizer,
    NeverDoneOptimizer,
    NotApplicableTask,
    ParallelTarget,
    StubOptimizer,
    StubTarget,
    StubTask,
)

# ---------------------------------------------------------------------------
# Helpers (test-local, too specific for conftest)
# ---------------------------------------------------------------------------


class VaryingScoreTask(StubTask):
    """Task whose evaluate() yields scores from an iterator."""

    def __init__(self, scores: list[float]) -> None:
        super().__init__()
        self._scores = iter(scores)

    async def evaluate(self, trajectory: Trajectory, target: object) -> EvaluationResult:
        return EvaluationResult(success=False, primary_score=Score(value=next(self._scores)))


class FailingRunTarget(StubTarget):
    """Target whose run() raises RuntimeError."""

    async def run(self, trajectory: object, send_event: object) -> None:
        raise RuntimeError("target exploded")


class FailingEvalTask(StubTask):
    """Task whose evaluate() raises RuntimeError."""

    async def evaluate(self, trajectory: object, target: object) -> EvaluationResult:
        raise RuntimeError("evaluation exploded")


class AlternatingSuccessTask(StubTask):
    """Task that succeeds on run 1, fails on run 2."""

    def __init__(self) -> None:
        super().__init__()
        self._call_count = 0

    async def evaluate(self, trajectory: Trajectory, target: object) -> EvaluationResult:
        self._call_count += 1
        return EvaluationResult(
            success=(self._call_count == 1),
            primary_score=Score(value=float(self._call_count)),
        )


# ---------------------------------------------------------------------------
# Controller init
# ---------------------------------------------------------------------------


class TestControllerInit:
    def test_construction_stores_params(self) -> None:
        controller = Controller(
            optimizer=StubOptimizer(),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        assert controller.event_log == []


# ---------------------------------------------------------------------------
# Controller run
# ---------------------------------------------------------------------------


class TestControllerRun:
    async def test_single_task_single_run(self) -> None:
        task = StubTask(score=0.75, success=False)
        controller = Controller(
            optimizer=StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([task]),
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()

        assert isinstance(result, ControllerResult)
        assert len(result.task_results) == 1
        tr = result.task_results[0]
        assert tr.task is task
        assert tr.best_score.value == 0.75
        assert tr.success is False
        assert len(tr.runs) == 1

    async def test_multiple_runs_until_done(self) -> None:
        controller = Controller(
            optimizer=CountingOptimizer(stop_after=3),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()
        assert len(result.task_results[0].runs) == 3

    async def test_max_runs_limit(self) -> None:
        controller = Controller(
            optimizer=StubOptimizer(done=False),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
            max_runs_per_task=3,
        )
        result = await controller.run()
        assert len(result.task_results[0].runs) == 3

    async def test_skipped_not_applicable_task(self) -> None:
        na_task = NotApplicableTask()
        controller = Controller(
            optimizer=StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([na_task, StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()
        assert len(result.task_results) == 1
        assert result.skipped_tasks == [na_task]

    async def test_teardown_called(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = StubTarget()
        controller = Controller(
            optimizer=optimizer, target=target,
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()
        assert optimizer.torn_down
        assert target.torn_down

    async def test_cleanup_called_after_each_run(self) -> None:
        target = StubTarget()
        controller = Controller(
            optimizer=StubOptimizer(done=False), target=target,
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG, max_runs_per_task=3,
        )
        await controller.run()
        assert target.cleanup_count == 3

    async def test_best_score_tracks_highest(self) -> None:
        controller = Controller(
            optimizer=CountingOptimizer(stop_after=3),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks(
                [VaryingScoreTask(scores=[0.2, 0.8, 0.5])]
            ),
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()
        assert result.task_results[0].best_score.value == 0.8


# ---------------------------------------------------------------------------
# Lifecycle events
# ---------------------------------------------------------------------------


class TestLifecycleEvents:
    async def test_optimizer_receives_lifecycle_events(self) -> None:
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer=optimizer, target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()
        types = [type(e).__name__ for e in optimizer.events_received]
        assert types[0] == "RunStartEvent"
        assert "ControllablePreCallEvent" in types
        assert types[-1] == "RunEndEvent"

    async def test_optimizer_trajectory_tracking(self) -> None:
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer=optimizer, target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()
        assert len(optimizer.past_trajectories) == 1
        assert optimizer.current_trajectory is None


# ---------------------------------------------------------------------------
# Security domain filtering
# ---------------------------------------------------------------------------


class TestSecurityDomainFiltering:
    async def test_in_scope_event_forwarded(self) -> None:
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer=optimizer, target=StubTarget(tag=EXTERNAL_TAG),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()
        ctrl_events = [e for e in optimizer.events_received
                       if isinstance(e, ControllablePreCallEvent)]
        assert len(ctrl_events) == 1

    async def test_out_of_scope_event_filtered(self) -> None:
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer=optimizer, target=StubTarget(tag=INTERNAL_TAG),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()
        ctrl_events = [e for e in optimizer.events_received
                       if isinstance(e, ControllablePreCallEvent)]
        assert len(ctrl_events) == 0
        ctrl_log = [(ev, r) for ev, r in controller.event_log
                    if isinstance(ev, ControllablePreCallEvent)]
        assert isinstance(ctrl_log[0][1], NoModification)

    async def test_parent_scope_includes_child(self) -> None:
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer=optimizer, target=StubTarget(tag=EXTERNAL_TAG),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=ROOT_TAG,
        )
        await controller.run()
        ctrl_events = [e for e in optimizer.events_received
                       if isinstance(e, ControllablePreCallEvent)]
        assert len(ctrl_events) == 1


# ---------------------------------------------------------------------------
# Parallel target
# ---------------------------------------------------------------------------


class TestParallelTarget:
    async def test_parallel_events_both_handled(self) -> None:
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer=optimizer, target=ParallelTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()
        ctrl_events = [e for e in optimizer.events_received
                       if isinstance(e, ControllablePreCallEvent)]
        assert len(ctrl_events) == 2
        assert {e.request for e in ctrl_events} == {"branch_a", "branch_b"}


# ---------------------------------------------------------------------------
# Feedback in trajectory
# ---------------------------------------------------------------------------


class TestFeedbackInTrajectory:
    async def test_feedback_entry_appended(self) -> None:
        controller = Controller(
            optimizer=StubOptimizer(), target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask(score=0.5)]),
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()
        entries = result.task_results[0].runs[0].trajectory.snapshot()
        feedback = [e for e in entries if e.entry_type is FEEDBACK]
        assert len(feedback) == 1
        assert feedback[0].content.evaluation.primary_score.value == 0.5


# ---------------------------------------------------------------------------
# Event log
# ---------------------------------------------------------------------------


class TestEventLog:
    async def test_event_log_populated(self) -> None:
        controller = Controller(
            optimizer=StubOptimizer(done=True), target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()
        ctrl_log = [(ev, r) for ev, r in controller.event_log
                    if isinstance(ev, ControllablePreCallEvent)]
        assert len(ctrl_log) == 1
        assert isinstance(ctrl_log[0][1], ControllableInjection)

    async def test_event_log_returns_defensive_copy(self) -> None:
        controller = Controller(
            optimizer=StubOptimizer(done=True), target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()
        log_copy = controller.event_log
        original_len = len(log_copy)
        assert original_len > 0
        log_copy.clear()
        assert len(controller.event_log) == original_len

    async def test_event_log_excludes_lifecycle_events(self) -> None:
        controller = Controller(
            optimizer=StubOptimizer(done=True), target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()
        lifecycle = [(ev, r) for ev, r in controller.event_log
                     if isinstance(ev, (RunStartEvent, RunEndEvent))]
        assert len(lifecycle) == 0


# ---------------------------------------------------------------------------
# Exception safety
# ---------------------------------------------------------------------------


class TestExceptionSafety:
    @pytest.mark.regression  # Fix: Controller.run() teardown wrapped in try/finally
    async def test_target_run_raises_propagates_and_cleans_up(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = FailingRunTarget()
        controller = Controller(
            optimizer=optimizer, target=target,
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        with pytest.raises(RuntimeError, match="target exploded"):
            await controller.run()
        assert optimizer.torn_down
        assert target.torn_down

    @pytest.mark.regression  # Fix: Controller.run() teardown wrapped in try/finally
    async def test_task_evaluate_raises_propagates_and_cleans_up(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = StubTarget()
        controller = Controller(
            optimizer=optimizer, target=target,
            security_claim=SecurityClaim.from_tasks([FailingEvalTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        with pytest.raises(RuntimeError, match="evaluation exploded"):
            await controller.run()
        assert optimizer.torn_down
        assert target.torn_down

    @pytest.mark.regression  # Fix: Optimizer._dispatch + run() exception safety
    async def test_optimizer_on_event_raises_propagates(self) -> None:
        optimizer = FailingOnEventOptimizer()
        target = StubTarget()
        controller = Controller(
            optimizer=optimizer, target=target,
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        with pytest.raises(RuntimeError, match="optimizer exploded"):
            await controller.run()
        assert optimizer.torn_down
        assert target.torn_down

    async def test_all_tasks_not_applicable(self) -> None:
        controller = Controller(
            optimizer=StubOptimizer(done=True), target=StubTarget(),
            security_claim=SecurityClaim.from_tasks(
                [NotApplicableTask(), NotApplicableTask()]
            ),
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()
        assert result.task_results == []
        assert len(result.skipped_tasks) == 2


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestControllerValidation:
    @pytest.mark.regression  # Fix: max_runs_per_task validated >= 1 in __init__
    @pytest.mark.parametrize("value", [0, -1, -100])
    def test_max_runs_per_task_invalid_raises(self, value: int) -> None:
        with pytest.raises(ValueError, match="at least 1"):
            Controller(
                optimizer=StubOptimizer(), target=StubTarget(),
                security_claim=SecurityClaim.from_tasks([StubTask()]),
                security_domain_tag=EXTERNAL_TAG, max_runs_per_task=value,
            )


# ---------------------------------------------------------------------------
# Run loop edge cases
# ---------------------------------------------------------------------------


class TestRunLoopEdgeCases:
    async def test_success_latches_true_across_runs(self) -> None:
        controller = Controller(
            optimizer=CountingOptimizer(stop_after=2),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([AlternatingSuccessTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()
        tr = result.task_results[0]
        assert tr.runs[0].evaluation.success is True
        assert tr.runs[1].evaluation.success is False
        assert tr.success is True  # latched

    async def test_never_done_runs_to_max(self) -> None:
        controller = Controller(
            optimizer=NeverDoneOptimizer(),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG, max_runs_per_task=3,
        )
        result = await controller.run()
        assert len(result.task_results[0].runs) == 3

    async def test_initialize_called_before_runs(self) -> None:
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer=optimizer, target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()
        assert optimizer.initialized

    async def test_trajectory_closed_after_run(self) -> None:
        controller = Controller(
            optimizer=StubOptimizer(done=True), target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()
        traj = result.task_results[0].runs[0].trajectory
        with pytest.raises(RuntimeError, match="closed"):
            traj.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="x"))
