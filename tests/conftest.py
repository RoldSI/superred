"""Shared fixtures for the superred test suite."""

from __future__ import annotations

import asyncio

import pytest

from superred.core.interfaces.optimizer import Optimizer
from superred.core.interfaces.target import EventHandler, Target
from superred.core.interfaces.task import NotApplicable, Task
from superred.core.types.controllable import Controllable, ControllableSpec
from superred.core.types.evaluation import EvaluationResult, Score
from superred.core.types.event import (
    ControllableInjection,
    ControllablePreCallEvent,
    Event,
    EventResponse,
    RunEndEvent,
    RunEndResponse,
    RunStartEvent,
)
from superred.core.types.goal import Goal
from superred.core.types.observable import ObservableValue
from superred.core.types.security_domain import SecurityDomain, SecurityDomainTag
from superred.core.types.state import ConfigSpec, QuerySpec
from superred.core.types.trajectory import Trajectory

# ---------------------------------------------------------------------------
# Security domain fixtures
# ---------------------------------------------------------------------------

ROOT_TAG = SecurityDomainTag("root")
EXTERNAL_TAG = SecurityDomainTag("external", parent=ROOT_TAG)
INTERNAL_TAG = SecurityDomainTag("internal", parent=ROOT_TAG)


def make_domain() -> SecurityDomain:
    """Build the test domain. Factored into a function so that conftest
    import does not crash if SecurityDomain construction is mutated
    (mutmut would otherwise report these as 'survived' due to exit code 4)."""
    return SecurityDomain([ROOT_TAG, EXTERNAL_TAG, INTERNAL_TAG])


@pytest.fixture
def root_tag() -> SecurityDomainTag:
    return ROOT_TAG


@pytest.fixture
def external_tag() -> SecurityDomainTag:
    return EXTERNAL_TAG


@pytest.fixture
def internal_tag() -> SecurityDomainTag:
    return INTERNAL_TAG


@pytest.fixture
def domain() -> SecurityDomain:
    return make_domain()


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

    def __init__(self, tag: SecurityDomainTag = EXTERNAL_TAG) -> None:
        self._tag = tag
        self._config: dict[str, str] = {}
        self.run_count = 0
        self.torn_down = False
        self.cleanup_count = 0

    @property
    def security_domain(self) -> SecurityDomain:
        return make_domain()

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
        self.cleanup_count += 1

    async def teardown(self) -> None:
        self.torn_down = True


class ParallelTarget(Target):
    """Target that fires two events concurrently from parallel branches."""

    def __init__(self, tag: SecurityDomainTag = EXTERNAL_TAG) -> None:
        self._tag = tag

    @property
    def security_domain(self) -> SecurityDomain:
        return make_domain()

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


class CountingOptimizer(Optimizer):
    """Optimizer that signals done after a configurable number of RunEndEvents."""

    def __init__(self, stop_after: int = 1, inject_value: str = "x") -> None:
        super().__init__()
        self._stop_after = stop_after
        self._inject_value = inject_value
        self._run_count = 0

    async def initialize(
        self, goal: Goal, controllables: list[Controllable],
        observables: list[ObservableValue],
    ) -> None:
        pass

    async def on_event(self, event: Event) -> EventResponse:
        if isinstance(event, RunStartEvent):
            return EventResponse(event=event)
        if isinstance(event, RunEndEvent):
            self._run_count += 1
            return RunEndResponse(event=event, done=self._run_count >= self._stop_after)
        return ControllableInjection(event=event, value=self._inject_value)

    async def teardown(self) -> None:
        pass


class NeverDoneOptimizer(Optimizer):
    """Optimizer that always returns done=False (never signals completion)."""

    async def initialize(
        self, goal: Goal, controllables: list[Controllable],
        observables: list[ObservableValue],
    ) -> None:
        pass

    async def on_event(self, event: Event) -> EventResponse:
        if isinstance(event, ControllablePreCallEvent):
            return ControllableInjection(event=event, value="x")
        if isinstance(event, RunEndEvent):
            return RunEndResponse(event=event, done=False)
        return EventResponse(event=event)

    async def teardown(self) -> None:
        pass


class FailingOnEventOptimizer(Optimizer):
    """Optimizer whose on_event raises on ControllablePreCallEvent."""

    def __init__(self) -> None:
        super().__init__()
        self.torn_down = False

    async def initialize(
        self, goal: Goal, controllables: list[Controllable],
        observables: list[ObservableValue],
    ) -> None:
        pass

    async def on_event(self, event: Event) -> EventResponse:
        if isinstance(event, ControllablePreCallEvent):
            raise RuntimeError("optimizer exploded")
        if isinstance(event, RunStartEvent):
            return EventResponse(event=event)
        if isinstance(event, RunEndEvent):
            return RunEndResponse(event=event, done=True)
        return EventResponse(event=event)

    async def teardown(self) -> None:
        self.torn_down = True
