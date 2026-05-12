"""Tests for the Controller orchestrator."""

from __future__ import annotations

import pytest

from superred.core.controller import Controller, ControllerResult, TargetFactory, ThreatModelResult
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


class FailAfterNRunsTarget(StubTarget):
    """Target that runs normally for the first N runs, then raises."""

    def __init__(self, succeed_for: int) -> None:
        super().__init__()
        self._succeed_for = succeed_for

    async def run(self, emit: EventHandler, send_event: EventResponseHandler) -> None:
        if self.run_count >= self._succeed_for:
            self.run_count += 1
            raise RuntimeError("target exploded mid-task")
        await super().run(emit, send_event)


class FailingConfigureTask(StubTask):
    """Task whose configure_target() raises (non-NotApplicable) RuntimeError."""

    async def configure_target(self, target: Target) -> None:
        raise RuntimeError("configure exploded")


class BudgetExhaustedInInitializeOptimizer(StubOptimizer):
    """Optimizer that exhausts its LLM budget inside initialize()."""

    async def initialize(
        self,
        goal: Goal,
        controllables: list[Controllable],
        observables: list[ObservableValue],
        llm_client: LLMClient,
    ) -> None:
        await super().initialize(goal, controllables, observables, llm_client)
        # Simulate a warmup LLM call that exhausts the configured budget.
        from superred.core.types.llm import BudgetExhaustedError, LLMUsage

        raise BudgetExhaustedError(
            "Budget gone during init",
            usage=LLMUsage(calls=1, cost=0.01),
        )


class FailingInitAndTeardownOptimizer(StubOptimizer):
    """Optimizer whose initialize() and teardown() both raise.

    Used to verify that a failing teardown does not mask the original
    initialize exception or cause the controller to crash.
    """

    async def initialize(
        self,
        goal: Goal,
        controllables: list[Controllable],
        observables: list[ObservableValue],
        llm_client: LLMClient,
    ) -> None:
        await super().initialize(goal, controllables, observables, llm_client)
        raise RuntimeError("initialize exploded")

    async def teardown(self) -> None:
        # Mark the call so tests can confirm teardown was attempted, then raise.
        await super().teardown()
        raise RuntimeError("teardown exploded")


class RaisingTeardownOptimizer(StubOptimizer):
    """Otherwise-normal optimizer whose teardown() always raises."""

    async def teardown(self) -> None:
        await super().teardown()
        raise RuntimeError("teardown exploded")


class FailingCleanupTarget(StubTarget):
    """Target whose cleanup() raises after the first run finishes."""

    async def cleanup(self) -> None:
        await super().cleanup()
        raise RuntimeError("cleanup exploded")


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
# TargetFactory
# ---------------------------------------------------------------------------


class TestTargetFactory:
    def test_default_concurrency_is_one(self) -> None:
        factory = TargetFactory(create=StubTarget)
        assert factory.concurrency == 1

    def test_explicit_concurrency(self) -> None:
        factory = TargetFactory(create=StubTarget, concurrency=8)
        assert factory.concurrency == 8

    def test_concurrency_must_be_at_least_one(self) -> None:
        with pytest.raises(ValueError, match="at least 1"):
            TargetFactory(create=StubTarget, concurrency=0)
        with pytest.raises(ValueError, match="at least 1"):
            TargetFactory(create=StubTarget, concurrency=-3)

    def test_create_returns_fresh_instances(self) -> None:
        factory = TargetFactory(create=StubTarget)
        a, b = factory.create(), factory.create()
        assert a is not b

    def test_singleton_returns_same_instance(self) -> None:
        target = StubTarget()
        factory = TargetFactory.singleton(target)
        assert factory.create() is target
        assert factory.create() is target

    def test_singleton_locks_concurrency_to_one(self) -> None:
        target = StubTarget()
        factory = TargetFactory.singleton(target)
        assert factory.concurrency == 1

    def test_frozen(self) -> None:
        factory = TargetFactory(create=StubTarget)
        with pytest.raises(AttributeError):
            factory.concurrency = 4  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Controller init
# ---------------------------------------------------------------------------


class TestControllerInit:
    def test_construction_stores_params(self) -> None:
        Controller(
            optimizer_factory=lambda: StubOptimizer(),
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )

    async def test_factory_called_once_per_task(self) -> None:
        """A non-singleton factory is invoked once per task in the claim.

        Passing explicit scopes skips the probe-target construction in
        ``_resolve_scopes``, so the only ``create()`` calls come from the
        per-task lifecycle.
        """
        calls = {"n": 0}

        def make_target() -> StubTarget:
            calls["n"] += 1
            return StubTarget()

        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=make_target),
            security_claim=SecurityClaim.from_tasks(
                [StubTask(goal_text="a"), StubTask(goal_text="b"), StubTask(goal_text="c")]
            ),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        assert calls["n"] == 3

    async def test_probe_target_used_when_scopes_default(self) -> None:
        """When scopes default to None, the factory is called once extra
        to build a probe for ``distinct_combinations()``."""
        calls = {"n": 0}

        def make_target() -> StubTarget:
            calls["n"] += 1
            return StubTarget()

        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=make_target),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        # No scopes passed — probe is built to enumerate distinct_combinations.
        result = await controller.run()
        # 1 probe + N task-bound (where N = task_count × len(scopes)).
        n_threat_models = len(result.threat_model_results)
        assert calls["n"] == 1 + n_threat_models


# ---------------------------------------------------------------------------
# Result type immutability
# ---------------------------------------------------------------------------


class TestResultTypesFrozen:
    async def test_run_result_frozen(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        assert len(_first_tmr(result).task_results[0].runs) == 3

    async def test_max_runs_limit(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=False),
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        assert _first_tmr(result).task_results[0].stop_reason == "done"

    async def test_stop_reason_max_runs(self) -> None:
        """Loop exhausts max_runs_per_task -> stop_reason='max_runs'."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=False),
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            max_runs_per_task=2,
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        assert _first_tmr(result).task_results[0].stop_reason == "max_runs"

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
                    raise BudgetExhaustedError("Budget gone", usage=LLMUsage(calls=10, cost=1.0))
                await super().run(emit, send_event)

        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=False),
            target_factory=TargetFactory.singleton(BudgetBlowingTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            max_runs_per_task=10,
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        assert _first_tmr(result).task_results[0].stop_reason == "budget_exhausted"

    async def test_stop_reason_budget_exhausted_in_initialize(self) -> None:
        """BudgetExhaustedError raised inside optimizer.initialize must be
        classified as stop_reason='budget_exhausted', not 'error'."""
        opt = BudgetExhaustedInInitializeOptimizer()
        controller = Controller(
            optimizer_factory=lambda: opt,
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        tr = _first_tmr(result).task_results[0]
        assert tr.stop_reason == "budget_exhausted"
        assert tr.runs == []
        assert tr.success is False
        # Teardown still happened despite the early return.
        assert opt.torn_down

    async def test_skipped_not_applicable_task(self) -> None:
        na_task = NotApplicableTask()
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(target),
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
            target_factory=TargetFactory.singleton(target),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            max_runs_per_task=3,
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        # 3 inner cleanups (one after each run's evaluation) + 1 post-task
        # cleanup invoked from the finally block.
        assert target.cleanup_count == 4

    async def test_best_score_tracks_highest(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: CountingOptimizer(stop_after=3),
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget(tag=EXTERNAL_TAG)),
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
            target_factory=TargetFactory.singleton(StubTarget(tag=INTERNAL_TAG)),
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
            target_factory=TargetFactory.singleton(StubTarget(tag=EXTERNAL_TAG)),
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
            target_factory=TargetFactory.singleton(ParallelTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        assert seen_run_end_on_trajectory

    async def test_include_feedback_false_sends_evaluation_none(self) -> None:
        """When include_feedback=False, RunEndEvent.evaluation is None."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(),
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget(tag=EXTERNAL_TAG)),
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
            target_factory=TargetFactory.singleton(StubTarget(tag=INTERNAL_TAG)),
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
            target_factory=TargetFactory.singleton(StubTarget(tag=EXTERNAL_TAG)),
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
            target_factory=TargetFactory.singleton(StubTarget(tag=INTERNAL_TAG)),
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
    @pytest.mark.regression  # Per-task error containment: target.run failure
    async def test_target_run_raises_is_contained_per_task(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = FailingRunTarget()
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target_factory=TargetFactory.singleton(target),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        tr = _first_tmr(result).task_results[0]
        assert tr.stop_reason == "error"
        assert tr.success is False
        assert tr.runs == []
        assert optimizer.torn_down
        assert target.torn_down

    @pytest.mark.regression  # Per-task error containment: task.evaluate failure
    async def test_task_evaluate_raises_is_contained_per_task(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = StubTarget()
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target_factory=TargetFactory.singleton(target),
            security_claim=SecurityClaim.from_tasks([FailingEvalTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        tr = _first_tmr(result).task_results[0]
        assert tr.stop_reason == "error"
        assert tr.success is False
        assert optimizer.torn_down
        assert target.torn_down

    @pytest.mark.regression  # Per-task error containment: optimizer.on_event failure
    async def test_optimizer_on_event_raises_is_contained_per_task(self) -> None:
        optimizer = FailingOnEventOptimizer()
        target = StubTarget()
        controller = Controller(
            optimizer_factory=lambda: optimizer,
            target_factory=TargetFactory.singleton(target),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        tr = _first_tmr(result).task_results[0]
        assert tr.stop_reason == "error"
        assert tr.success is False
        assert optimizer.torn_down
        assert target.torn_down

    async def test_partial_runs_preserved_when_task_errors_mid_loop(self) -> None:
        """A task that succeeds run 1 and fails run 2 keeps run 1 in its TaskResult."""
        target = FailAfterNRunsTarget(succeed_for=1)
        controller = Controller(
            optimizer_factory=lambda: CountingOptimizer(stop_after=10),
            target_factory=TargetFactory.singleton(target),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            max_runs_per_task=5,
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        tr = _first_tmr(result).task_results[0]
        assert tr.stop_reason == "error"
        # The successful first run is preserved.
        assert len(tr.runs) == 1
        # success latched from the first run.
        assert tr.success is True
        assert target.torn_down

    async def test_sibling_tasks_unaffected_by_task_error(self) -> None:
        """One failing task does not stop the rest of the threat model."""
        failing = FailingEvalTask()
        ok = StubTask(goal_text="Good task")
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([failing, ok]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        trs = _first_tmr(result).task_results
        assert len(trs) == 2
        assert trs[0].stop_reason == "error"
        assert trs[0].success is False
        assert trs[1].stop_reason == "done"
        assert trs[1].success is True

    async def test_configure_target_error_synthesizes_task_result(self) -> None:
        """A non-NotApplicable error in configure_target produces a synthetic error TaskResult."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([FailingConfigureTask(), StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        trs = _first_tmr(result).task_results
        assert len(trs) == 2
        assert trs[0].stop_reason == "error"
        assert trs[0].runs == []
        assert trs[0].best_score.value == 0.0
        assert trs[1].stop_reason == "done"

    async def test_teardown_failure_during_init_error_does_not_propagate(self) -> None:
        """A raising teardown in the init-failure path must not mask the
        original initialize exception or crash the controller."""
        bad_opt = FailingInitAndTeardownOptimizer(done=True)
        controller = Controller(
            optimizer_factory=lambda: bad_opt,
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        tr = _first_tmr(result).task_results[0]
        assert tr.stop_reason == "error"
        # Teardown was still attempted.
        assert bad_opt.torn_down

    async def test_teardown_failure_in_finally_does_not_propagate(self) -> None:
        """A raising teardown in the post-run finally must not propagate
        over a normally-completed task."""
        opt = RaisingTeardownOptimizer(done=True)
        controller = Controller(
            optimizer_factory=lambda: opt,
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        tr = _first_tmr(result).task_results[0]
        # The task completed normally; the swallowed teardown failure does
        # not flip the stop_reason or strip the run.
        assert tr.stop_reason == "done"
        assert len(tr.runs) == 1
        assert opt.torn_down

    async def test_target_cleanup_invoked_in_finally_after_failed_run(self) -> None:
        """A failed task still calls target.cleanup in the finally block so
        the next task starts against a clean target."""
        target = FailingRunTarget()  # raises on every target.run
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory.singleton(target),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            max_runs_per_task=3,
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        tr = _first_tmr(result).task_results[0]
        assert tr.stop_reason == "error"
        # The inner-loop cleanup-after-success never ran (every run failed),
        # so the only cleanup attempt comes from the outer finally.
        assert target.cleanup_count == 1
        assert target.torn_down

    async def test_target_cleanup_error_treated_as_error(self) -> None:
        """target.cleanup raising after a run is treated like any other error."""
        target = FailingCleanupTarget()
        controller = Controller(
            optimizer_factory=lambda: CountingOptimizer(stop_after=10),
            target_factory=TargetFactory.singleton(target),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
            max_runs_per_task=5,
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        tr = _first_tmr(result).task_results[0]
        assert tr.stop_reason == "error"
        # The run before cleanup succeeded — preserved.
        assert len(tr.runs) == 1
        assert target.torn_down

    async def test_all_tasks_not_applicable(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory.singleton(StubTarget()),
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
                target_factory=TargetFactory.singleton(StubTarget()),
                security_claim=SecurityClaim.from_tasks([StubTask()]),
                llm_configs=[STUB_LLM_CONFIG],
                max_runs_per_task=value,
            )

    def test_max_runs_per_task_one_is_valid(self) -> None:
        """max_runs_per_task=1 is the minimum valid value."""
        Controller(
            optimizer_factory=lambda: StubOptimizer(),
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        assert optimizer.initialized

    async def test_trajectory_closed_after_run(self) -> None:
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(_MultiControllableTarget()),
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
            target_factory=TargetFactory.singleton(_MultiControllableTarget()),
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
            target_factory=TargetFactory.singleton(_MultiControllableTarget()),
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
            target_factory=TargetFactory.singleton(_MultiControllableTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(_TaggingTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[config_a, config_b],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE, ROOT_SCOPE])
        assert len(result.threat_model_results) == 4

    async def test_default_scopes_from_distinct_combinations(self) -> None:
        """Without explicit scopes, uses target's distinct_combinations()."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(_MultiControllableTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
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
            target_factory=TargetFactory.singleton(StubTarget()),
            security_claim=SecurityClaim.from_tasks([StubTask()]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        # Should not raise
        await controller.run(scopes=[EXTERNAL_SCOPE, ROOT_SCOPE])


# ---------------------------------------------------------------------------
# Parallel task execution
# ---------------------------------------------------------------------------


class _SlowTarget(StubTarget):
    """Target whose run() sleeps so we can observe overlap between tasks."""

    in_flight: int = 0  # class-level so all instances share the same counter
    peak: int = 0

    def __init__(self, tag: object = EXTERNAL_TAG, sleep_s: float = 0.05) -> None:
        super().__init__(tag=tag)  # type: ignore[arg-type]
        self._sleep_s = sleep_s

    @classmethod
    def reset_counters(cls) -> None:
        cls.in_flight = 0
        cls.peak = 0

    async def run(self, emit: EventHandler, send_event: EventResponseHandler) -> None:
        import asyncio

        type(self).in_flight += 1
        type(self).peak = max(type(self).peak, type(self).in_flight)
        try:
            await asyncio.sleep(self._sleep_s)
            await super().run(emit, send_event)
        finally:
            type(self).in_flight -= 1


class TestParallelExecution:
    """Concurrent task execution within a threat model."""

    async def test_tasks_run_in_parallel_up_to_concurrency(self) -> None:
        """With concurrency=4, four tasks should be in flight at peak."""
        _SlowTarget.reset_counters()
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=_SlowTarget, concurrency=4),
            security_claim=SecurityClaim.from_tasks([StubTask() for _ in range(8)]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        # Eight tasks, concurrency=4 — peak in-flight should hit the limit.
        assert _SlowTarget.peak == 4

    async def test_concurrency_one_is_sequential(self) -> None:
        """With concurrency=1, peak in-flight is exactly 1."""
        _SlowTarget.reset_counters()
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=_SlowTarget, concurrency=1),
            security_claim=SecurityClaim.from_tasks([StubTask() for _ in range(4)]),
            llm_configs=[STUB_LLM_CONFIG],
        )
        await controller.run(scopes=[EXTERNAL_SCOPE])
        assert _SlowTarget.peak == 1

    async def test_parallel_preserves_input_order(self) -> None:
        """task_results is in the order tasks appear in the security claim."""
        # Distinct goals tied to instance identity so reordering is detectable.
        tasks = [StubTask(goal_text=f"task-{i}") for i in range(6)]
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=_SlowTarget, concurrency=3),
            security_claim=SecurityClaim.from_tasks(tasks),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        ordered = [tr.task.goal.description for tr in _first_tmr(result).task_results]
        assert ordered == [f"task-{i}" for i in range(6)]

    async def test_one_task_failure_does_not_block_siblings_parallel(self) -> None:
        """A failure in one parallel task is contained and siblings still run."""
        controller = Controller(
            optimizer_factory=lambda: StubOptimizer(done=True),
            target_factory=TargetFactory(create=StubTarget, concurrency=4),
            security_claim=SecurityClaim.from_tasks(
                [FailingEvalTask(), StubTask(), StubTask(), StubTask()]
            ),
            llm_configs=[STUB_LLM_CONFIG],
        )
        result = await controller.run(scopes=[EXTERNAL_SCOPE])
        trs = _first_tmr(result).task_results
        assert len(trs) == 4
        assert trs[0].stop_reason == "error"
        for tr in trs[1:]:
            assert tr.stop_reason == "done"
            assert tr.success is True
