"""Tests for the Controller orchestrator and EventChannel."""

from __future__ import annotations

import asyncio

import pytest

from superred.core.channel import EventChannel
from superred.core.controller import Controller, ControllerResult
from superred.core.interfaces.optimizer import Optimizer
from superred.core.interfaces.security_claim import SecurityClaim
from superred.core.interfaces.target import EventHandler, Target
from superred.core.interfaces.task import NotApplicable, Task
from superred.core.middleware import Middleware, compose, security_domain_filter
from superred.core.types.controllable import Controllable, ControllableSpec
from superred.core.types.evaluation import EvaluationResult, Score
from superred.core.types.event import (
    ControllableInjection,
    ControllablePreCallEvent,
    Event,
    EventResponse,
    NoModification,
    RunEndEvent,
    RunEndResponse,
    RunStartEvent,
)
from superred.core.types.goal import Goal
from superred.core.types.observable import ObservableValue
from superred.core.types.security_domain import SecurityDomain, SecurityDomainTag
from superred.core.types.state import ConfigSpec, QuerySpec
from superred.core.types.trajectory import FEEDBACK, Trajectory

# ---------------------------------------------------------------------------
# Security domain fixtures
# ---------------------------------------------------------------------------

ROOT_TAG = SecurityDomainTag("root")
EXTERNAL_TAG = SecurityDomainTag("external", parent=ROOT_TAG)
INTERNAL_TAG = SecurityDomainTag("internal", parent=ROOT_TAG)

DOMAIN = SecurityDomain([ROOT_TAG, EXTERNAL_TAG, INTERNAL_TAG])


# ---------------------------------------------------------------------------
# Stub implementations
# ---------------------------------------------------------------------------


class StubOptimizer(Optimizer):
    """Minimal optimizer that injects a fixed value."""

    def __init__(self, inject_value: str = "injected", done: bool = False) -> None:
        super().__init__()
        self.inject_value = inject_value
        self._done = done
        self.events_received: list[Event] = []
        self.initialized = False
        self.torn_down = False

    async def initialize(
        self,
        goal: Goal,
        controllables: list[Controllable],
        observables: list[ObservableValue],
    ) -> None:
        self.initialized = True

    async def on_event(self, event: Event) -> EventResponse:
        self.events_received.append(event)
        if isinstance(event, RunStartEvent):
            return EventResponse(event=event)
        if isinstance(event, RunEndEvent):
            return RunEndResponse(event=event, done=self._done)
        return ControllableInjection(event=event, value=self.inject_value)

    async def teardown(self) -> None:
        self.torn_down = True


class StubTarget(Target):
    """Minimal target that emits one controllable event per run."""

    def __init__(
        self,
        tag: SecurityDomainTag = EXTERNAL_TAG,
    ) -> None:
        self._tag = tag
        self._config: dict[str, str] = {}
        self.run_count = 0
        self.torn_down = False

    @property
    def security_domain(self) -> SecurityDomain:
        return DOMAIN

    @property
    def config_specs(self) -> list[ConfigSpec]:
        return [ConfigSpec(name="prompt", security_domain=self._tag, description="The prompt")]

    def set_config(self, name: str, value: str) -> None:
        self._config[name] = value

    @property
    def query_specs(self) -> list[QuerySpec]:
        return [QuerySpec(name="last_response", description="The last response")]

    def query(self, name: str, **params: str) -> str:
        return "target_response"

    def get_controllables(self) -> list[Controllable]:
        spec = ControllableSpec(name="user_input", security_domain=self._tag)
        return [Controllable(spec=spec)]

    def get_observables(self) -> list[ObservableValue]:
        return []

    async def run(self, trajectory: Trajectory, send_event: EventHandler) -> None:
        self.run_count += 1
        controllable = Controllable(
            spec=ControllableSpec(name="user_input", security_domain=self._tag)
        )
        event = ControllablePreCallEvent(controllable=controllable, request="hello")
        await send_event(event)

    async def cleanup(self) -> None:
        pass

    async def teardown(self) -> None:
        self.torn_down = True


class ParallelTarget(Target):
    """Target that fires two events concurrently from parallel branches."""

    def __init__(self, tag: SecurityDomainTag = EXTERNAL_TAG) -> None:
        self._tag = tag

    @property
    def security_domain(self) -> SecurityDomain:
        return DOMAIN

    @property
    def config_specs(self) -> list[ConfigSpec]:
        return []

    def set_config(self, name: str, value: str) -> None:
        pass

    @property
    def query_specs(self) -> list[QuerySpec]:
        return []

    def query(self, name: str, **params: str) -> str:
        return ""

    def get_controllables(self) -> list[Controllable]:
        return []

    def get_observables(self) -> list[ObservableValue]:
        return []

    async def run(self, trajectory: Trajectory, send_event: EventHandler) -> None:
        spec = ControllableSpec(name="parallel_input", security_domain=self._tag)

        async def branch(request: str) -> EventResponse:
            controllable = Controllable(spec=spec)
            event = ControllablePreCallEvent(controllable=controllable, request=request)
            return await send_event(event)

        # Fire two events concurrently
        r1, r2 = await asyncio.gather(branch("branch_a"), branch("branch_b"))
        assert isinstance(r1, ControllableInjection)
        assert isinstance(r2, ControllableInjection)

    async def cleanup(self) -> None:
        pass

    async def teardown(self) -> None:
        pass


class StubTask(Task[Target]):
    """Minimal task that returns a fixed evaluation result."""

    def __init__(
        self,
        score: float = 1.0,
        success: bool = True,
        goal_text: str = "Test goal",
    ) -> None:
        self._goal = Goal(description=goal_text)
        self._score = score
        self._success = success

    @property
    def goal(self) -> Goal:
        return self._goal

    async def configure_target(self, target: Target) -> None:
        pass

    async def evaluate(self, trajectory: Trajectory, target: Target) -> EvaluationResult:
        return EvaluationResult(
            success=self._success,
            primary_score=Score(value=self._score),
        )


class NotApplicableTask(Task[Target]):
    """Task that always raises NotApplicable."""

    @property
    def goal(self) -> Goal:
        return Goal(description="N/A task")

    async def configure_target(self, target: Target) -> None:
        raise NotApplicable("Not applicable to this target")

    async def evaluate(self, trajectory: Trajectory, target: Target) -> EvaluationResult:
        raise AssertionError("Should not be called")


# ---------------------------------------------------------------------------
# EventChannel tests
# ---------------------------------------------------------------------------


class TestEventChannel:
    """Unit tests for EventChannel and EventEnvelope."""

    async def test_send_receive_respond(self) -> None:
        channel = EventChannel()
        event = RunStartEvent(trajectory=Trajectory())

        async def receiver() -> None:
            envelope = await channel.receive()
            assert envelope is not None
            assert envelope.event is event
            envelope.respond(EventResponse(event=event))

        recv_task = asyncio.create_task(receiver())
        response = await channel.send(event)
        await recv_task

        assert isinstance(response, EventResponse)
        assert response.event is event

    async def test_close_signals_none(self) -> None:
        channel = EventChannel()
        channel.close()
        envelope = await channel.receive()
        assert envelope is None

    async def test_async_iteration(self) -> None:
        channel = EventChannel()
        events_seen: list[Event] = []

        async def consumer() -> None:
            async for envelope in channel:
                events_seen.append(envelope.event)
                envelope.respond(EventResponse(event=envelope.event))

        consumer_task = asyncio.create_task(consumer())

        e1 = RunStartEvent(trajectory=Trajectory())
        e2 = RunEndEvent(trajectory=Trajectory())
        await channel.send(e1)
        await channel.send(e2)
        channel.close()
        await consumer_task

        assert len(events_seen) == 2

    async def test_double_respond_raises(self) -> None:
        channel = EventChannel()
        event = RunStartEvent(trajectory=Trajectory())

        async def receiver() -> None:
            envelope = await channel.receive()
            assert envelope is not None
            envelope.respond(EventResponse(event=event))
            with pytest.raises(RuntimeError, match="more than once"):
                envelope.respond(EventResponse(event=event))

        recv_task = asyncio.create_task(receiver())
        await channel.send(event)
        await recv_task

    async def test_double_close_is_safe(self) -> None:
        channel = EventChannel()
        channel.close()
        channel.close()  # should not raise
        assert await channel.receive() is None


# ---------------------------------------------------------------------------
# Controller init tests
# ---------------------------------------------------------------------------


class TestControllerInit:
    """Constructor validation."""

    def test_construction(self) -> None:
        target = StubTarget()
        optimizer = StubOptimizer()
        claim = SecurityClaim.from_tasks([StubTask()])

        Controller(
            optimizer=optimizer,
            target=target,
            security_claim=claim,
            security_domain_tag=EXTERNAL_TAG,
        )


# ---------------------------------------------------------------------------
# Controller run tests
# ---------------------------------------------------------------------------


class TestControllerRun:
    """End-to-end run loop."""

    async def test_single_task_single_run(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = StubTarget()
        task = StubTask(score=0.75, success=False)
        claim = SecurityClaim.from_tasks([task])

        controller = Controller(
            optimizer=optimizer,
            target=target,
            security_claim=claim,
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()

        assert isinstance(result, ControllerResult)
        assert len(result.task_results) == 1
        assert len(result.skipped_tasks) == 0

        tr = result.task_results[0]
        assert tr.task is task
        assert tr.best_score.value == 0.75
        assert tr.success is False
        assert len(tr.runs) == 1

    async def test_multiple_runs_until_done(self) -> None:
        """Optimizer signals done after 3 runs."""
        call_count = 0

        class DoneAfterThreeOptimizer(Optimizer):
            def __init__(self) -> None:
                super().__init__()

            async def initialize(
                self, goal: Goal, controllables: list[Controllable],
                observables: list[ObservableValue],
            ) -> None:
                pass

            async def on_event(self, event: Event) -> EventResponse:
                nonlocal call_count
                if isinstance(event, RunStartEvent):
                    return EventResponse(event=event)
                if isinstance(event, RunEndEvent):
                    call_count += 1
                    return RunEndResponse(event=event, done=call_count >= 3)
                return ControllableInjection(event=event, value="x")

            async def teardown(self) -> None:
                pass

        optimizer = DoneAfterThreeOptimizer()
        target = StubTarget()
        claim = SecurityClaim.from_tasks([StubTask()])

        controller = Controller(
            optimizer=optimizer,
            target=target,
            security_claim=claim,
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()

        assert len(result.task_results[0].runs) == 3

    async def test_max_runs_limit(self) -> None:
        """Optimizer never signals done — max_runs_per_task caps the loop."""
        optimizer = StubOptimizer(done=False)
        target = StubTarget()
        claim = SecurityClaim.from_tasks([StubTask()])

        controller = Controller(
            optimizer=optimizer,
            target=target,
            security_claim=claim,
            security_domain_tag=EXTERNAL_TAG,
            max_runs_per_task=3,
        )
        result = await controller.run()

        assert len(result.task_results[0].runs) == 3

    async def test_skipped_not_applicable_task(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = StubTarget()
        na_task = NotApplicableTask()
        ok_task = StubTask()
        claim = SecurityClaim.from_tasks([na_task, ok_task])

        controller = Controller(
            optimizer=optimizer,
            target=target,
            security_claim=claim,
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()

        assert len(result.task_results) == 1
        assert len(result.skipped_tasks) == 1
        assert result.skipped_tasks[0] is na_task

    async def test_teardown_called(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = StubTarget()
        claim = SecurityClaim.from_tasks([StubTask()])

        controller = Controller(
            optimizer=optimizer,
            target=target,
            security_claim=claim,
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()

        assert optimizer.torn_down
        assert target.torn_down


# ---------------------------------------------------------------------------
# Lifecycle event tests
# ---------------------------------------------------------------------------


class TestLifecycleEvents:
    """RunStartEvent / RunEndEvent delivered to optimizer."""

    async def test_optimizer_receives_lifecycle_events(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = StubTarget()
        claim = SecurityClaim.from_tasks([StubTask()])

        controller = Controller(
            optimizer=optimizer,
            target=target,
            security_claim=claim,
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()

        types = [type(e).__name__ for e in optimizer.events_received]
        assert types[0] == "RunStartEvent"
        assert "ControllablePreCallEvent" in types
        assert types[-1] == "RunEndEvent"

    async def test_optimizer_trajectory_tracking(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = StubTarget()
        claim = SecurityClaim.from_tasks([StubTask()])

        controller = Controller(
            optimizer=optimizer,
            target=target,
            security_claim=claim,
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()

        # After run, trajectory should be in past_trajectories
        assert len(optimizer.past_trajectories) == 1
        assert optimizer.current_trajectory is None


# ---------------------------------------------------------------------------
# Security domain filtering tests
# ---------------------------------------------------------------------------


class TestSecurityDomainFiltering:
    """Events outside the active security domain are filtered."""

    async def test_in_scope_event_forwarded(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = StubTarget(tag=EXTERNAL_TAG)
        claim = SecurityClaim.from_tasks([StubTask()])

        controller = Controller(
            optimizer=optimizer,
            target=target,
            security_claim=claim,
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()

        # Optimizer should have received the controllable event
        controllable_events = [
            e for e in optimizer.events_received if isinstance(e, ControllablePreCallEvent)
        ]
        assert len(controllable_events) == 1

    async def test_out_of_scope_event_filtered(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = StubTarget(tag=INTERNAL_TAG)
        claim = SecurityClaim.from_tasks([StubTask()])

        controller = Controller(
            optimizer=optimizer,
            target=target,
            security_claim=claim,
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()

        # Optimizer should NOT have received controllable events
        controllable_events = [
            e for e in optimizer.events_received if isinstance(e, ControllablePreCallEvent)
        ]
        assert len(controllable_events) == 0

        # Event log should show NoModification
        controllable_log = [
            (ev, resp)
            for ev, resp in controller.event_log
            if isinstance(ev, ControllablePreCallEvent)
        ]
        assert len(controllable_log) == 1
        assert isinstance(controllable_log[0][1], NoModification)

    async def test_parent_scope_includes_child(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = StubTarget(tag=EXTERNAL_TAG)
        claim = SecurityClaim.from_tasks([StubTask()])

        controller = Controller(
            optimizer=optimizer,
            target=target,
            security_claim=claim,
            security_domain_tag=ROOT_TAG,
        )
        await controller.run()

        controllable_events = [
            e for e in optimizer.events_received if isinstance(e, ControllablePreCallEvent)
        ]
        assert len(controllable_events) == 1


# ---------------------------------------------------------------------------
# Parallel target tests
# ---------------------------------------------------------------------------


class TestParallelTarget:
    """Target with concurrent branches sending events simultaneously."""

    async def test_parallel_events_both_handled(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = ParallelTarget()
        claim = SecurityClaim.from_tasks([StubTask()])

        controller = Controller(
            optimizer=optimizer,
            target=target,
            security_claim=claim,
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()

        # Both parallel events should have been handled
        controllable_events = [
            e for e in optimizer.events_received if isinstance(e, ControllablePreCallEvent)
        ]
        assert len(controllable_events) == 2
        requests = {e.request for e in controllable_events}
        assert requests == {"branch_a", "branch_b"}


# ---------------------------------------------------------------------------
# Feedback in trajectory tests
# ---------------------------------------------------------------------------


class TestFeedbackInTrajectory:
    """Evaluation feedback is appended to the trajectory."""

    async def test_feedback_entry_appended(self) -> None:
        optimizer = StubOptimizer()
        target = StubTarget()
        claim = SecurityClaim.from_tasks([StubTask(score=0.5)])

        controller = Controller(
            optimizer=optimizer,
            target=target,
            security_claim=claim,
            security_domain_tag=EXTERNAL_TAG,
        )
        result = await controller.run()

        trajectory = result.task_results[0].runs[0].trajectory
        entries = trajectory.snapshot()

        feedback_entries = [e for e in entries if e.entry_type is FEEDBACK]
        assert len(feedback_entries) == 1
        assert feedback_entries[0].content.evaluation.primary_score.value == 0.5


# ---------------------------------------------------------------------------
# Event log tests
# ---------------------------------------------------------------------------


class TestEventLog:
    """Event log tracks all event-response pairs."""

    async def test_event_log_populated(self) -> None:
        optimizer = StubOptimizer(done=True)
        target = StubTarget()
        claim = SecurityClaim.from_tasks([StubTask()])

        controller = Controller(
            optimizer=optimizer,
            target=target,
            security_claim=claim,
            security_domain_tag=EXTERNAL_TAG,
        )
        await controller.run()

        # Should have at least the controllable event
        controllable_log = [
            (ev, resp)
            for ev, resp in controller.event_log
            if isinstance(ev, ControllablePreCallEvent)
        ]
        assert len(controllable_log) == 1
        assert isinstance(controllable_log[0][1], ControllableInjection)


# ---------------------------------------------------------------------------
# Middleware tests
# ---------------------------------------------------------------------------


class TestMiddleware:
    """Tests for middleware compose and security_domain_filter."""

    async def test_compose_identity(self) -> None:
        """compose() with no middlewares returns the handler unchanged."""
        calls: list[Event] = []

        async def handler(event: Event) -> EventResponse:
            calls.append(event)
            return EventResponse(event=event)

        wrapped = compose()(handler)
        event = RunStartEvent(trajectory=Trajectory())
        await wrapped(event)
        assert len(calls) == 1

    async def test_compose_ordering(self) -> None:
        """Middlewares apply left-to-right (first listed = outermost)."""
        order: list[str] = []

        def make_mw(name: str) -> Middleware:
            def mw(handler: EventHandler) -> EventHandler:
                async def wrapped(event: Event) -> EventResponse:
                    order.append(f"{name}_before")
                    resp = await handler(event)
                    order.append(f"{name}_after")
                    return resp
                return wrapped
            return mw

        async def inner(event: Event) -> EventResponse:
            order.append("inner")
            return EventResponse(event=event)

        wrapped = compose(make_mw("a"), make_mw("b"))(inner)
        await wrapped(RunStartEvent(trajectory=Trajectory()))

        assert order == ["a_before", "b_before", "inner", "b_after", "a_after"]

    async def test_security_filter_blocks_out_of_scope(self) -> None:
        """security_domain_filter blocks events outside scope."""
        log: list[tuple[Event, EventResponse]] = []

        async def handler(event: Event) -> EventResponse:
            return ControllableInjection(event=event, value="x")

        filtered = security_domain_filter(EXTERNAL_TAG, event_log=log)(handler)

        # INTERNAL_TAG is NOT included by EXTERNAL_TAG
        controllable = Controllable(
            spec=ControllableSpec(name="c", security_domain=INTERNAL_TAG)
        )
        event = ControllablePreCallEvent(controllable=controllable, request="hi")
        response = await filtered(event)

        assert isinstance(response, NoModification)
        assert len(log) == 1

    async def test_security_filter_passes_in_scope(self) -> None:
        """security_domain_filter forwards events in scope."""
        log: list[tuple[Event, EventResponse]] = []

        async def handler(event: Event) -> EventResponse:
            return ControllableInjection(event=event, value="x")

        filtered = security_domain_filter(EXTERNAL_TAG, event_log=log)(handler)

        controllable = Controllable(
            spec=ControllableSpec(name="c", security_domain=EXTERNAL_TAG)
        )
        event = ControllablePreCallEvent(controllable=controllable, request="hi")
        response = await filtered(event)

        assert isinstance(response, ControllableInjection)
        assert len(log) == 1

    async def test_security_filter_passes_non_controllable(self) -> None:
        """Non-controllable events pass through regardless."""

        async def handler(event: Event) -> EventResponse:
            return EventResponse(event=event)

        filtered = security_domain_filter(EXTERNAL_TAG)(handler)
        event = RunStartEvent(trajectory=Trajectory())
        response = await filtered(event)

        assert isinstance(response, EventResponse)
