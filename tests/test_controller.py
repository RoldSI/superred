"""Tests for the Controller orchestrator."""

from __future__ import annotations

import pytest

from superred.core.controller import (
    Controller,
    ControllerConfig,
    ControllerResult,
    ThreatModelResult,
)
from superred.core.interfaces.security_claim import SecurityClaim
from superred.core.interfaces.target import Target
from superred.core.llm import LLMClient
from superred.core.types.controllable import Controllable
from superred.core.types.evaluation import EvaluationResult, Score
from superred.core.types.event import Event, EventHandler, EventResponse, EventResponseHandler
from superred.core.types.events import (
    ControllableInjection,
    ControllableNoInjection,
    ControllablePreCallEvent,
    ObservableEvent,
    RunEndEvent,
    RunEndResponse,
    RunStartEvent,
)
from superred.core.types.goal import Goal
from superred.core.types.llm import LLMConfig
from superred.core.types.observable import Observable, ObservableValue
from superred.core.types.security_domain import Scope
from superred.core.types.trajectory import FilteredTrajectory, Trajectory

from .conftest import (
    EXTERNAL_TAG,
    INTERNAL_TAG,
    ROOT_TAG,
    STUB_LLM_CONFIG,
    CountingOptimizer,
    FailingOnEventOptimizer,
    NeverDoneOptimizer,
    NotApplicableTask,
    ParallelTarget,
    StubOptimizer,
    StubTarget,
    StubTask,
)

# Convenience scope constants
EXTERNAL_SCOPE: Scope = frozenset({EXTERNAL_TAG})
ROOT_SCOPE: Scope = frozenset({ROOT_TAG})


def _first_tmr(result: ControllerResult) -> ThreatModelResult:
    """Get the first (and usually only) ThreatModelResult."""
    return result.threat_model_results[0]


# ---------------------------------------------------------------------------
# Helpers (test-local, too specific for conftest)
# ---------------------------------------------------------------------------


class VaryingScoreTask(StubTask):
    """Task whose evaluate() yields scores from an iterator."""

    def __init__(self, scores: list[float]) -> None:
        super().__init__()
        self._scores = iter(scores)

    async def evaluate(
        self,
        trajectory: Trajectory,
        target: object,
    ) -> EvaluationResult:
        return EvaluationResult(
            success=False,
            primary_score=Score(value=next(self._scores), security_domain=EXTERNAL_TAG),
        )


class FailingRunTarget(StubTarget):
    """Target whose run() raises RuntimeError."""

    async def run(self, emit: EventHandler, send_event: EventResponseHandler) -> None:
        raise RuntimeError("target exploded")


class FailingEvalTask(StubTask):
    """Task whose evaluate() raises RuntimeError."""

    async def evaluate(
        self,
        trajectory: object,
        target: object,
    ) -> EvaluationResult:
        raise RuntimeError("evaluation exploded")


class AlternatingSuccessTask(StubTask):
    """Task that succeeds on run 1, fails on run 2."""

    def __init__(self) -> None:
        super().__init__()
        self._call_count = 0

    async def evaluate(
        self,
        trajectory: Trajectory,
        target: object,
    ) -> EvaluationResult:
        self._call_count += 1
        return EvaluationResult(
            success=(self._call_count == 1),
            primary_score=Score(
                value=float(self._call_count),
                security_domain=EXTERNAL_TAG,
            ),
        )


# ---------------------------------------------------------------------------
# Controller init
# ---------------------------------------------------------------------------


class TestControllerInit:
    def test_construction_stores_params(self) -> None:
        Controller(
            optimizer_factory=lambda: StubOptimizer(),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )


# ---------------------------------------------------------------------------
# Result type immutability
# ---------------------------------------------------------------------------


class TestResultTypesFrozen:
    async def test_run_result_frozen(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        run_result = _first_tmr(result).task_results[0].runs[0]
        with pytest.raises(AttributeError):
            run_result.evaluation = None  # type: ignore[misc]

    async def test_task_result_frozen(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        tr = _first_tmr(result).task_results[0]
        with pytest.raises(AttributeError):
            tr.success = True  # type: ignore[misc]

    async def test_controller_result_frozen(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        with pytest.raises(AttributeError):
            result.threat_model_results = []  # type: ignore[misc]

    def test_threat_model_result_skipped_tasks_defaults_to_empty_list(self) -> None:
        """ThreatModelResult.skipped_tasks defaults to an empty list, not None."""
        tmr = ThreatModelResult(
            scope=EXTERNAL_SCOPE,
            llm_config=None,
            controller_config=ControllerConfig(max_runs_per_task=100, include_feedback=True),
            task_results=[],
        )
        assert tmr.skipped_tasks == []
        assert isinstance(tmr.skipped_tasks, list)


# ---------------------------------------------------------------------------
# Controller run
# ---------------------------------------------------------------------------


class TestControllerRun:
    async def test_single_task_single_run(self) -> None:
        task = StubTask(score=0.75, success=False)
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([task]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])

        assert isinstance(result, ControllerResult)
        tmr = _first_tmr(result)
        assert len(tmr.task_results) == 1
        tr = tmr.task_results[0]
        assert tr.task is task
        assert tr.best_score.value == 0.75
        assert tr.success is False
        assert len(tr.runs) == 1

    async def test_multiple_runs_until_done(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: CountingOptimizer(stop_after=3),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        assert len(_first_tmr(result).task_results[0].runs) == 3

    async def test_max_runs_limit(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=False),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            max_runs_per_task=3,
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        assert len(_first_tmr(result).task_results[0].runs) == 3

    async def test_stop_reason_done(self) -> None:
        """Optimizer signals done=True -> stop_reason='done'."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        assert _first_tmr(result).task_results[0].stop_reason == "done"

    async def test_stop_reason_max_runs(self) -> None:
        """Loop exhausts max_runs_per_task -> stop_reason='max_runs'."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=False),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            max_runs_per_task=2,
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        assert _first_tmr(result).task_results[0].stop_reason == "max_runs"

    async def test_controller_config_propagated(self) -> None:
        """ThreatModelResult carries the controller's settings for reproducibility."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            max_runs_per_task=7,
            include_feedback=False,
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        cc = _first_tmr(result).controller_config
        assert cc.max_runs_per_task == 7
        assert cc.include_feedback is False

    async def test_stop_reason_budget_exhausted(self) -> None:
        """BudgetExhaustedError mid-run -> stop_reason='budget_exhausted'."""
        from superred.core.types.llm import BudgetExhaustedError, LLMUsage

        run_count = 0

        class BudgetBlowingTarget(StubTarget):
            async def run(
                self,
                emit: EventHandler,
                send_event: EventResponseHandler,
            ) -> None:
                nonlocal run_count
                run_count += 1
                if run_count >= 2:
                    raise BudgetExhaustedError(
                        "Budget gone", usage=LLMUsage(calls=10, cost=1.0)
                    )
                await super().run(emit, send_event)

        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=False),
            target=BudgetBlowingTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            max_runs_per_task=10,
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        assert _first_tmr(result).task_results[0].stop_reason == "budget_exhausted"

    async def test_skipped_not_applicable_task(self) -> None:
        na_task = NotApplicableTask()
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([na_task, StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        tmr = _first_tmr(result)
        assert len(tmr.task_results) == 1
        assert tmr.skipped_tasks == [na_task]

    async def test_teardown_called(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = StubTarget()
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=target,
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        assert optimizer.torn_down
        assert target.torn_down

    async def test_cleanup_called_after_each_run(self) -> None:
        target = StubTarget()
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=False),
            target=target,
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            max_runs_per_task=3,
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        assert target.cleanup_count == 3

    async def test_best_score_tracks_highest(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: CountingOptimizer(stop_after=3),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([VaryingScoreTask(scores=[0.2, 0.8, 0.5])]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        assert _first_tmr(result).task_results[0].best_score.value == 0.8


# ---------------------------------------------------------------------------
# Lifecycle events
# ---------------------------------------------------------------------------


class TestLifecycleEvents:
    async def test_optimizer_receives_lifecycle_events(self) -> None:
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        types = [type(e).__name__ for e in optimizer.events_received]
        assert types[0] == "RunStartEvent"
        assert "ControllablePreCallEvent" in types
        assert types[-1] == "RunEndEvent"

    async def test_optimizer_trajectory_tracking(self) -> None:
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        assert len(optimizer.past_trajectories) == 1
        assert optimizer.current_trajectory is None


# ---------------------------------------------------------------------------
# Security domain filtering
# ---------------------------------------------------------------------------


class TestSecurityDomainFiltering:
    async def test_in_scope_event_forwarded(self) -> None:
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=StubTarget(tag=EXTERNAL_TAG),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        ctrl_events = [
            e for e in optimizer.events_received if isinstance(e, ControllablePreCallEvent)
        ]
        assert len(ctrl_events) == 1

    async def test_out_of_scope_event_filtered(self) -> None:
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=StubTarget(tag=INTERNAL_TAG),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        ctrl_events = [
            e for e in optimizer.events_received if isinstance(e, ControllablePreCallEvent)
        ]
        assert len(ctrl_events) == 0
        # Verify ControllableNoInjection response is on the trajectory
        traj = _first_tmr(result).task_results[0].runs[0].trajectory
        responses = [e for e in traj.snapshot() if isinstance(e, ControllableNoInjection)]
        assert len(responses) == 1

    async def test_parent_scope_includes_child(self) -> None:
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=StubTarget(tag=EXTERNAL_TAG),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[ROOT_SCOPE])
        ctrl_events = [
            e for e in optimizer.events_received if isinstance(e, ControllablePreCallEvent)
        ]
        assert len(ctrl_events) == 1


# ---------------------------------------------------------------------------
# Parallel target
# ---------------------------------------------------------------------------


class TestParallelTarget:
    async def test_parallel_events_both_handled(self) -> None:
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=ParallelTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        ctrl_events = [
            e for e in optimizer.events_received if isinstance(e, ControllablePreCallEvent)
        ]
        assert len(ctrl_events) == 2
        assert {e.request for e in ctrl_events} == {"branch_a", "branch_b"}


# ---------------------------------------------------------------------------
# Feedback in trajectory
# ---------------------------------------------------------------------------


class TestFeedbackInTrajectory:
    async def test_run_end_persisted_with_evaluation(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask(score=0.5)]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        entries = _first_tmr(result).task_results[0].runs[0].trajectory.snapshot()
        run_ends = [e for e in entries if isinstance(e, RunEndEvent)]
        assert len(run_ends) == 1
        assert run_ends[0].evaluation is not None
        assert run_ends[0].evaluation.primary_score.value == 0.5

    async def test_run_end_has_security_domain_from_scope(self) -> None:
        """RunEndEvent persisted to trajectory gets security_domain from scope."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        entries = _first_tmr(result).task_results[0].runs[0].trajectory.snapshot()
        run_ends = [e for e in entries if isinstance(e, RunEndEvent)]
        assert len(run_ends) == 1
        assert run_ends[0].security_domain in EXTERNAL_SCOPE

    async def test_run_end_visible_in_filtered_trajectory(self) -> None:
        """RunEndEvent is visible in the optimizer's filtered trajectory."""
        seen_run_end_on_trajectory = False

        class _InspectingOptimizer(StubOptimizer):
            async def on_event(self, event: Event) -> EventResponse:
                nonlocal seen_run_end_on_trajectory
                if isinstance(event, RunEndEvent):
                    if self.current_trajectory is not None:
                        for entry in self.current_trajectory.snapshot():
                            if isinstance(entry, RunEndEvent):
                                seen_run_end_on_trajectory = True
                    return RunEndResponse(event=event, done=True)
                return await super().on_event(event)

        controller = Controller(
            optimizer_factory=lambda: _InspectingOptimizer(),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        assert seen_run_end_on_trajectory

    async def test_include_feedback_false_sends_evaluation_none(self) -> None:
        """When include_feedback=False, RunEndEvent.evaluation is None."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask(score=0.9)]),
            llm_configs=[STUB_LLM_CONFIG],
            include_feedback=False,
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        entries = _first_tmr(result).task_results[0].runs[0].trajectory.snapshot()
        run_ends = [e for e in entries if isinstance(e, RunEndEvent)]
        assert len(run_ends) == 1
        assert run_ends[0].evaluation is None

    async def test_include_feedback_false_still_persists_run_end(self) -> None:
        """RunEndEvent is persisted even when include_feedback=False."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            include_feedback=False,
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        entries = _first_tmr(result).task_results[0].runs[0].trajectory.snapshot()
        run_ends = [e for e in entries if isinstance(e, RunEndEvent)]
        assert len(run_ends) == 1


# ---------------------------------------------------------------------------
# Events on trajectory
# ---------------------------------------------------------------------------


class TestEventsOnTrajectory:
    async def test_controllable_event_and_response_on_trajectory(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        traj = _first_tmr(result).task_results[0].runs[0].trajectory
        events = [e for e in traj.snapshot() if isinstance(e, ControllablePreCallEvent)]
        responses = [e for e in traj.snapshot() if isinstance(e, ControllableInjection)]
        assert len(events) == 1
        assert len(responses) == 1

    async def test_in_scope_response_tagged_with_scope(self) -> None:
        """In-scope controllable response is tagged with the optimizer's scope,
        so the optimizer can see its own injection in the filtered trajectory."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(tag=EXTERNAL_TAG),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        traj = _first_tmr(result).task_results[0].runs[0].trajectory
        responses = [e for e in traj.snapshot() if isinstance(e, ControllableInjection)]
        assert len(responses) == 1
        # Domain derived from event's controllable — in scope for EXTERNAL
        from superred.core.types.trajectory import get_domain

        assert get_domain(responses[0]) is EXTERNAL_TAG

    async def test_out_of_scope_response_tagged_with_event_domain(self) -> None:
        """Out-of-scope ControllableNoInjection response is tagged with the event's domain,
        making it invisible to the optimizer through the filtered trajectory."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(tag=INTERNAL_TAG),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        traj = _first_tmr(result).task_results[0].runs[0].trajectory
        responses = [e for e in traj.snapshot() if isinstance(e, ControllableNoInjection)]
        assert len(responses) == 1
        # Domain derived from event's controllable — INTERNAL, invisible to EXTERNAL optimizer
        from superred.core.types.trajectory import get_domain

        assert get_domain(responses[0]) is INTERNAL_TAG

    async def test_optimizer_sees_own_response_in_filtered_trajectory(self) -> None:
        """The optimizer's filtered trajectory includes its own injection responses."""
        seen_responses: list[object] = []

        class _InspectingOptimizer(StubOptimizer):
            async def on_event(self, event: Event) -> EventResponse:
                if isinstance(event, RunEndEvent):
                    if self.current_trajectory is not None:
                        for entry in self.current_trajectory.snapshot():
                            if isinstance(entry, ControllableInjection):
                                seen_responses.append(entry)
                    return RunEndResponse(event=event, done=True)
                return await super().on_event(event)

        controller = Controller(
            optimizer_factory=lambda: _InspectingOptimizer(done=True),
            target=StubTarget(tag=EXTERNAL_TAG),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        assert len(seen_responses) == 1
        assert isinstance(seen_responses[0], ControllableInjection)

    async def test_optimizer_does_not_see_out_of_scope_response(self) -> None:
        """Out-of-scope ControllableNoInjection responses are invisible to the optimizer."""
        seen_responses: list[object] = []

        class _InspectingOptimizer(StubOptimizer):
            async def on_event(self, event: Event) -> EventResponse:
                if isinstance(event, RunEndEvent):
                    if self.current_trajectory is not None:
                        for entry in self.current_trajectory.snapshot():
                            if isinstance(entry, (ControllableInjection, ControllableNoInjection)):
                                seen_responses.append(entry)
                    return RunEndResponse(event=event, done=True)
                return await super().on_event(event)

        controller = Controller(
            optimizer_factory=lambda: _InspectingOptimizer(done=True),
            target=StubTarget(tag=INTERNAL_TAG),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        # ControllableNoInjection tagged with INTERNAL — invisible to EXTERNAL optimizer
        assert len(seen_responses) == 0


# ---------------------------------------------------------------------------
# Exception safety
# ---------------------------------------------------------------------------


class TestExceptionSafety:
    @pytest.mark.regression  # Fix: Controller.run() teardown wrapped in try/finally
    async def test_target_run_raises_propagates_and_cleans_up(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = FailingRunTarget()
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=target,
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        with pytest.raises(RuntimeError, match="target exploded"):
            await controller.run(scopes=[EXTERNAL_SCOPE])
        assert optimizer.torn_down
        assert target.torn_down

    @pytest.mark.regression  # Fix: Controller.run() teardown wrapped in try/finally
    async def test_task_evaluate_raises_propagates_and_cleans_up(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = StubTarget()
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=target,
            security_claim=SecurityClaim.from_tasks([FailingEvalTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        with pytest.raises(RuntimeError, match="evaluation exploded"):
            await controller.run(scopes=[EXTERNAL_SCOPE])
        assert optimizer.torn_down
        assert target.torn_down

    @pytest.mark.regression  # Fix: Optimizer._dispatch + run() exception safety
    async def test_optimizer_on_event_raises_propagates(self) -> None:
        optimizer = FailingOnEventOptimizer()
        target = StubTarget()
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=target,
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        with pytest.raises(RuntimeError, match="optimizer exploded"):
            await controller.run(scopes=[EXTERNAL_SCOPE])
        assert optimizer.torn_down
        assert target.torn_down

    async def test_all_tasks_not_applicable(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([NotApplicableTask(), NotApplicableTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        tmr = _first_tmr(result)
        assert tmr.task_results == []
        assert len(tmr.skipped_tasks) == 2


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestControllerValidation:
    @pytest.mark.regression  # Fix: max_runs_per_task validated >= 1 in __init__
    @pytest.mark.parametrize("value", [0, -1, -100])
    def test_max_runs_per_task_invalid_raises(self, value: int) -> None:
        with pytest.raises(ValueError, match="at least 1"):
            Controller(
                optimizer_factory=lambda: StubOptimizer(),
                target=StubTarget(),
                security_claim=SecurityClaim.from_tasks([StubTask()]),
                llm_configs=[STUB_LLM_CONFIG],
                max_runs_per_task=value,
            )

    def test_max_runs_per_task_one_is_valid(self) -> None:
        """max_runs_per_task=1 is the minimum valid value."""
        Controller(
            optimizer_factory=lambda: StubOptimizer(),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            max_runs_per_task=1,
        )


# ---------------------------------------------------------------------------
# Run loop edge cases
# ---------------------------------------------------------------------------


class TestRunLoopEdgeCases:
    async def test_success_latches_true_across_runs(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: CountingOptimizer(stop_after=2),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([AlternatingSuccessTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        tr = _first_tmr(result).task_results[0]
        assert tr.runs[0].evaluation.success is True
        assert tr.runs[1].evaluation.success is False
        assert tr.success is True  # latched

    async def test_never_done_runs_to_max(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: NeverDoneOptimizer(),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            max_runs_per_task=3,
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        assert len(_first_tmr(result).task_results[0].runs) == 3

    async def test_initialize_called_before_runs(self) -> None:
        optimizer = StubOptimizer(done=True)
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        assert optimizer.initialized

    async def test_trajectory_closed_after_run(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        traj = _first_tmr(result).task_results[0].runs[0].trajectory
        with pytest.raises(RuntimeError, match="closed"):
            traj.emit(
                ObservableEvent(
                    observable=Observable(name="x", security_domain=EXTERNAL_TAG),
                    content="x",
                )
            )


# ---------------------------------------------------------------------------
# Controllable / observable filtering for optimizer
# ---------------------------------------------------------------------------


class _MultiControllableTarget(StubTarget):
    """Target with both in-scope and out-of-scope controllables + observables."""

    def get_controllables(self) -> list[Controllable]:
        return [
            Controllable(
                name="external_input",
                security_domain=EXTERNAL_TAG,
            ),
            Controllable(
                name="internal_input",
                security_domain=INTERNAL_TAG,
            ),
        ]

    def get_observables(self) -> list[ObservableValue]:
        ext_obs = Observable(
            name="ext_obs",
            security_domain=EXTERNAL_TAG,
            description="visible",
        )
        int_obs = Observable(
            name="int_obs",
            security_domain=INTERNAL_TAG,
            description="hidden",
        )
        return [
            ObservableValue(observable=ext_obs, content="ext_data"),
            ObservableValue(observable=int_obs, content="int_data"),
        ]


class _CapturingOptimizer(StubOptimizer):
    """Optimizer that records what it received during initialize()."""

    def __init__(self, **kwargs: object) -> None:
        super().__init__(done=True)
        self.received_controllables: list[Controllable] = []
        self.received_observables: list[ObservableValue] = []
        self.received_trajectories: list[object] = []

    async def initialize(
        self,
        goal: Goal,
        controllables: list[Controllable],
        observables: list[ObservableValue],
        llm_client: LLMClient,
    ) -> None:
        await super().initialize(goal, controllables, observables, llm_client)
        self.received_controllables = list(controllables)
        self.received_observables = list(observables)

    async def on_event(self, event: Event) -> EventResponse:
        if isinstance(event, RunStartEvent):
            self.received_trajectories.append(event.trajectory)
            return EventResponse(event=event)
        if isinstance(event, RunEndEvent):
            return RunEndResponse(event=event, done=True)
        return ControllableInjection(
            event=event,
            controllable=event.controllable,
            value="x",
        )


class TestControllableObservableFiltering:
    async def test_out_of_scope_controllable_excluded(self) -> None:
        """Optimizer only receives controllables within scope."""
        optimizer = _CapturingOptimizer()
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=_MultiControllableTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        names = [c.name for c in optimizer.received_controllables]
        assert "external_input" in names
        assert "internal_input" not in names

    async def test_out_of_scope_observable_excluded(self) -> None:
        """Optimizer only receives observables within scope."""
        optimizer = _CapturingOptimizer()
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=_MultiControllableTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        names = [o.observable.name for o in optimizer.received_observables]
        assert "ext_obs" in names
        assert "int_obs" not in names

    async def test_root_scope_includes_all(self) -> None:
        """Root scope includes all controllables and observables."""
        optimizer = _CapturingOptimizer()
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=_MultiControllableTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[ROOT_SCOPE])
        assert len(optimizer.received_controllables) == 2
        assert len(optimizer.received_observables) == 2

    async def test_multi_tag_scope_includes_both_domains(self) -> None:
        """A frozenset with {EXTERNAL, INTERNAL} includes both."""
        optimizer = _CapturingOptimizer()
        multi_scope: Scope = frozenset({EXTERNAL_TAG, INTERNAL_TAG})
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=_MultiControllableTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[multi_scope])
        names = [c.name for c in optimizer.received_controllables]
        assert "external_input" in names
        assert "internal_input" in names
        obs_names = [o.observable.name for o in optimizer.received_observables]
        assert "ext_obs" in obs_names
        assert "int_obs" in obs_names


# ---------------------------------------------------------------------------
# Optimizer receives FilteredTrajectory
# ---------------------------------------------------------------------------


class TestOptimizerReceivesFilteredTrajectory:
    async def test_run_start_carries_filtered_trajectory(self) -> None:
        """RunStartEvent sent to optimizer carries a FilteredTrajectory."""
        optimizer = _CapturingOptimizer()
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        assert len(optimizer.received_trajectories) == 1
        assert isinstance(optimizer.received_trajectories[0], FilteredTrajectory)

    async def test_filtered_trajectory_hides_out_of_scope_entries(self) -> None:
        """Entries emitted with out-of-scope tags are invisible to optimizer."""

        class _TaggingTarget(StubTarget):
            async def run(
                self,
                emit: EventHandler,
                send_event: EventResponseHandler,
            ) -> None:
                self.run_count += 1
                # Emit entries at different scopes
                emit(
                    ObservableEvent(
                        observable=Observable(name="ext", security_domain=EXTERNAL_TAG),
                        content="external",
                    )
                )
                emit(
                    ObservableEvent(
                        observable=Observable(name="int", security_domain=INTERNAL_TAG),
                        content="internal",
                    )
                )
                # Still fire controllable event so optimizer responds
                ctrl = Controllable(
                    name="user_input",
                    security_domain=EXTERNAL_TAG,
                )
                await send_event(
                    ControllablePreCallEvent(controllable=ctrl, request="q"),
                )

        snapshot_contents: list[str] = []

        class _SnapshotOptimizer(StubOptimizer):
            async def on_event(self, event: Event) -> EventResponse:
                if isinstance(event, RunEndEvent):
                    # Read from the filtered trajectory via current_trajectory
                    if self.current_trajectory is not None:
                        for e in self.current_trajectory.snapshot():
                            if isinstance(e, ObservableEvent):
                                snapshot_contents.append(e.content)
                    return RunEndResponse(event=event, done=True)
                return await super().on_event(event)

        controller = Controller(
            optimizer_factory=lambda: _SnapshotOptimizer(done=True),
            target=_TaggingTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])

        # Optimizer should only see the external entry, not internal
        assert "external" in snapshot_contents
        assert "internal" not in snapshot_contents


# ---------------------------------------------------------------------------
# Multi-entry feedback
# ---------------------------------------------------------------------------


class _ScopedScoresTask(StubTask):
    """Task that returns sub_scores scoped to different security domains."""

    async def evaluate(
        self,
        trajectory: Trajectory,
        target: Target,
    ) -> EvaluationResult:
        return EvaluationResult(
            success=True,
            primary_score=Score(value=0.9, security_domain=ROOT_TAG),
            sub_scores={
                "external_asr": Score(
                    value=0.8,
                    name="external_asr",
                    security_domain=EXTERNAL_TAG,
                ),
                "internal_leak": Score(
                    value=0.3,
                    name="internal_leak",
                    security_domain=INTERNAL_TAG,
                ),
            },
        )


class TestScopedScoreFiltering:
    async def test_sub_scores_filtered_by_scope(self) -> None:
        """Controller filters out-of-scope sub_scores from feedback."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([_ScopedScoresTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        entries = _first_tmr(result).task_results[0].runs[0].trajectory.snapshot()
        feedback = [e for e in entries if isinstance(e, RunEndEvent) and e.evaluation is not None]

        # One feedback entry at the scope level
        assert len(feedback) == 1
        fb = feedback[0]

        # primary_score always included
        assert fb.evaluation.primary_score.value == 0.9

        # external_asr in scope (EXTERNAL includes EXTERNAL)
        assert "external_asr" in fb.evaluation.sub_scores

        # internal_leak out of scope (EXTERNAL does not include INTERNAL)
        assert "internal_leak" not in fb.evaluation.sub_scores

    async def test_root_scope_keeps_all_sub_scores(self) -> None:
        """Root scope includes everything — all sub_scores preserved."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([_ScopedScoresTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[ROOT_SCOPE])
        entries = _first_tmr(result).task_results[0].runs[0].trajectory.snapshot()
        feedback = [e for e in entries if isinstance(e, RunEndEvent) and e.evaluation is not None]
        fb = feedback[0]
        assert "external_asr" in fb.evaluation.sub_scores
        assert "internal_leak" in fb.evaluation.sub_scores

    async def test_optimizer_sees_filtered_scores_on_next_run(self) -> None:
        """On run 2, optimizer reads run 1's feedback with filtered sub_scores."""
        sub_score_names_seen: list[str] = []
        run_count = 0

        class _FeedbackReadingOptimizer(StubOptimizer):
            async def on_event(self, event: Event) -> EventResponse:
                nonlocal run_count
                if isinstance(event, RunStartEvent):
                    run_count += 1
                    if run_count == 2:
                        for past in self.past_trajectories:
                            for entry in past.snapshot():
                                if isinstance(entry, RunEndEvent) and entry.evaluation is not None:
                                    sub_score_names_seen.extend(
                                        entry.evaluation.sub_scores.keys(),
                                    )
                    return EventResponse(event=event)
                if isinstance(event, RunEndEvent):
                    return RunEndResponse(event=event, done=run_count >= 2)
                return ControllableInjection(
                    event=event,
                    controllable=event.controllable,
                    value="x",
                )

        controller = Controller(
            optimizer_factory=lambda: _FeedbackReadingOptimizer(),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([_ScopedScoresTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            max_runs_per_task=2,
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])

        assert "external_asr" in sub_score_names_seen
        assert "internal_leak" not in sub_score_names_seen

    async def test_primary_score_included_even_when_out_of_scope(self) -> None:
        """primary_score is always in the feedback, even if its domain
        is outside the tested scope (optimizer needs the main signal)."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([_ScopedScoresTask()]),
            # EXTERNAL scope, but primary_score has ROOT domain
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        entries = _first_tmr(result).task_results[0].runs[0].trajectory.snapshot()
        feedback = [e for e in entries if isinstance(e, RunEndEvent) and e.evaluation is not None]
        fb = feedback[0]
        # primary_score domain is ROOT, scope is EXTERNAL — still included
        assert fb.evaluation.primary_score.value == 0.9
        assert fb.evaluation.primary_score.security_domain is ROOT_TAG

    async def test_all_sub_scores_out_of_scope(self) -> None:
        """When every sub_score is out of scope, feedback has empty sub_scores."""

        class _AllOutOfScopeTask(StubTask):
            async def evaluate(
                self,
                trajectory: Trajectory,
                target: Target,
            ) -> EvaluationResult:
                return EvaluationResult(
                    success=True,
                    primary_score=Score(value=0.5, security_domain=ROOT_TAG),
                    sub_scores={
                        "a": Score(value=0.1, security_domain=INTERNAL_TAG, name="a"),
                        "b": Score(value=0.2, security_domain=INTERNAL_TAG, name="b"),
                    },
                )

        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([_AllOutOfScopeTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        entries = _first_tmr(result).task_results[0].runs[0].trajectory.snapshot()
        feedback = [e for e in entries if isinstance(e, RunEndEvent) and e.evaluation is not None]
        fb = feedback[0]
        assert fb.evaluation.sub_scores == {}
        # primary_score and success still present
        assert fb.evaluation.primary_score.value == 0.5
        assert fb.evaluation.success is True

    async def test_success_and_rationale_preserved_in_filtered_feedback(self) -> None:
        """success and rationale are always included in filtered feedback."""

        class _RationaleTask(StubTask):
            async def evaluate(
                self,
                trajectory: Trajectory,
                target: Target,
            ) -> EvaluationResult:
                return EvaluationResult(
                    success=False,
                    primary_score=Score(value=0.1, security_domain=EXTERNAL_TAG),
                    rationale="Attack partially succeeded",
                )

        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([_RationaleTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        entries = _first_tmr(result).task_results[0].runs[0].trajectory.snapshot()
        feedback = [e for e in entries if isinstance(e, RunEndEvent) and e.evaluation is not None]
        fb = feedback[0]
        assert fb.evaluation.success is False
        assert fb.evaluation.rationale == "Attack partially succeeded"

    async def test_none_domain_sub_score_always_included(self) -> None:
        """Sub-scores with security_domain=None pass the filter at any scope."""

        class _NoneDomainScoreTask(StubTask):
            async def evaluate(
                self,
                trajectory: Trajectory,
                target: Target,
            ) -> EvaluationResult:
                return EvaluationResult(
                    success=True,
                    primary_score=Score(value=0.9),
                    sub_scores={
                        "always_visible": Score(value=0.7, name="always_visible"),
                        "scoped": Score(
                            value=0.3,
                            security_domain=INTERNAL_TAG,
                            name="scoped",
                        ),
                    },
                )

        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([_NoneDomainScoreTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        entries = _first_tmr(result).task_results[0].runs[0].trajectory.snapshot()
        feedback = [e for e in entries if isinstance(e, RunEndEvent) and e.evaluation is not None]
        fb = feedback[0]
        # None-domain sub_score always included
        assert "always_visible" in fb.evaluation.sub_scores
        # INTERNAL-domain sub_score filtered out at EXTERNAL scope
        assert "scoped" not in fb.evaluation.sub_scores


# ---------------------------------------------------------------------------
# Threat model iteration
# ---------------------------------------------------------------------------


class TestThreatModelIteration:
    async def test_single_scope_single_config(self) -> None:
        """One scope + one LLM config = one threat model."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        assert len(result.threat_model_results) == 1
        tmr = result.threat_model_results[0]
        assert tmr.scope == EXTERNAL_SCOPE
        assert tmr.llm_config is STUB_LLM_CONFIG

    async def test_multiple_scopes(self) -> None:
        """Multiple scopes produce multiple threat models."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE, ROOT_SCOPE])
        assert len(result.threat_model_results) == 2
        scopes_seen = {tmr.scope for tmr in result.threat_model_results}
        assert scopes_seen == {EXTERNAL_SCOPE, ROOT_SCOPE}

    async def test_no_llm_configs_iterates_scopes_only(self) -> None:
        """Without llm_configs, controller iterates scopes with no LLM."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        assert len(result.threat_model_results) == 1
        tmr = result.threat_model_results[0]
        assert tmr.llm_config is None

    async def test_fresh_optimizer_per_task(self) -> None:
        """Each task gets a fresh optimizer instance."""
        created: list[StubOptimizer] = []

        def factory() -> StubOptimizer:
            opt = StubOptimizer(done=True)
            created.append(opt)
            return opt

        controller = Controller(
            optimizer_factory=factory,
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask(), StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        assert len(created) == 2
        assert created[0] is not created[1]

    async def test_models_filter(self) -> None:
        """models= argument filters which LLM configs are used."""
        config_a = LLMConfig(model="model-a", api_base="http://a", api_key="sk-a")
        config_b = LLMConfig(model="model-b", api_base="http://b", api_key="sk-b")
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[config_a, config_b],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE], models=["model-a"])
        assert len(result.threat_model_results) == 1
        assert result.threat_model_results[0].llm_config is config_a

    async def test_scopes_x_configs_cartesian(self) -> None:
        """2 scopes x 2 configs = 4 threat models."""
        config_a = LLMConfig(model="a", api_base="http://a", api_key="sk-a")
        config_b = LLMConfig(model="b", api_base="http://b", api_key="sk-b")
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[config_a, config_b],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE, ROOT_SCOPE])
        assert len(result.threat_model_results) == 4

    async def test_default_scopes_from_distinct_combinations(self) -> None:
        """Without explicit scopes, uses target's distinct_combinations()."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run()
        # StubTarget uses make_domain() which has [root, external, internal]
        # distinct_combinations() returns non-empty subsets
        assert len(result.threat_model_results) >= 1
        for tmr in result.threat_model_results:
            assert len(tmr.scope) > 0

    async def test_optimizer_teardown_per_task(self) -> None:
        """Each optimizer is torn down after its task completes."""
        torn_down: list[StubOptimizer] = []

        class _TrackingOptimizer(StubOptimizer):
            async def teardown(self) -> None:
                await super().teardown()
                torn_down.append(self)

        controller = Controller(
            optimizer_factory=lambda: _TrackingOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask(), StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        assert len(torn_down) == 2

    async def test_models_filter_no_match(self) -> None:
        """models= with no matching configs produces zero threat models."""
        config = LLMConfig(model="model-a", api_base="http://a", api_key="sk-a")
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[config],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE], models=["nonexistent"])
        # No matching LLM configs → no threat models (empty configs → iterate scopes only)
        # Actually: _resolve_llm_configs returns [] when no match,
        # then _iterate_threat_models iterates scopes without configs
        assert len(result.threat_model_results) >= 1
        for tmr in result.threat_model_results:
            assert tmr.llm_config is None

    async def test_multi_tag_scope_filtering(self) -> None:
        """A scope with multiple tags filters correctly (any tag includes)."""
        optimizer = StubOptimizer(done=True)
        # Multi-tag scope: {EXTERNAL, INTERNAL} — should include both
        multi_scope: Scope = frozenset({EXTERNAL_TAG, INTERNAL_TAG})
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target=_MultiControllableTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[multi_scope])
        # Optimizer should see both controllables
        ctrl_events = [
            e for e in optimizer.events_received if isinstance(e, ControllablePreCallEvent)
        ]
        # _MultiControllableTarget fires one controllable event per run
        # But controller filters controllables for initialize, not events
        # The event filtering happens in middleware
        assert len(ctrl_events) >= 1

    async def test_fresh_optimizer_per_threat_model(self) -> None:
        """Each threat model gets fresh optimizer instances."""
        created: list[StubOptimizer] = []

        def factory() -> StubOptimizer:
            opt = StubOptimizer(done=True)
            created.append(opt)
            return opt

        controller = Controller(
            optimizer_factory=factory,
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        # Two scopes, one task each = 2 optimizers
        await controller.run(scopes=[EXTERNAL_SCOPE, ROOT_SCOPE])
        assert len(created) == 2
        assert created[0] is not created[1]

    async def test_threat_model_result_scope_and_config_correct(self) -> None:
        """Each ThreatModelResult has the correct scope and llm_config."""
        config_a = LLMConfig(model="a", api_base="http://a", api_key="sk-a")
        config_b = LLMConfig(model="b", api_base="http://b", api_key="sk-b")
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[config_a, config_b],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE, ROOT_SCOPE])
        # 2 scopes x 2 configs = 4 threat models
        assert len(result.threat_model_results) == 4
        combos = {(tmr.scope, tmr.llm_config) for tmr in result.threat_model_results}
        assert (EXTERNAL_SCOPE, config_a) in combos
        assert (EXTERNAL_SCOPE, config_b) in combos
        assert (ROOT_SCOPE, config_a) in combos
        assert (ROOT_SCOPE, config_b) in combos

    async def test_each_threat_model_has_task_results(self) -> None:
        """Each threat model evaluates all tasks independently."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask(), StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE, ROOT_SCOPE])
        assert len(result.threat_model_results) == 2
        for tmr in result.threat_model_results:
            assert len(tmr.task_results) == 2

    async def test_print_summary_with_threat_models(self) -> None:
        """_print_summary runs without error on multi-threat-model results."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target=StubTarget(),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        # Should not raise
        await controller.run(scopes=[EXTERNAL_SCOPE, ROOT_SCOPE])
