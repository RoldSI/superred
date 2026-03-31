"""Tests for Protocol-based interfaces using runtime_checkable."""

from typing import Any, Mapping, Optional, Sequence

from superred.core.interfaces.target import TargetModuleInterface, TargetRunInterface
from superred.core.interfaces.task import (
    BoundTaskTargetInterface,
    EvaluatedRunInterface,
    SecurityClaim,
    TaskModuleInterface,
)
from superred.core.types.context import (
    ActionRecord,
    ObservationRecord,
    TurnResult,
)
from superred.core.types.security_claims import ClaimVerdict, OracleEvidence
from superred.core.types.task import TaskDefinition, TaskFeedback
from superred.core.types.threat_model import (
    Budget,
    InterfaceRole,
    InterfaceSpec,
    PropertyKind,
    RuntimeParamSpec,
    SecurityDomain,
    TargetMetadata,
    ThreatModel,
)
from superred.core.types.trajectory import EventKind, TraceEvent


class _MockTargetRun:
    def __init__(self, tm: ThreatModel):
        self._tm = tm
        self._trace: list[TraceEvent] = []

    def threat_model(self) -> ThreatModel:
        return self._tm

    def available_controllables(self) -> Sequence[InterfaceSpec]:
        return []

    def available_observables(self) -> Sequence[InterfaceSpec]:
        return []

    def apply_controllables(self, values: Mapping[str, Any]) -> None:
        pass

    def step(self) -> TurnResult:
        return TurnResult(action=None, observation=None, new_events=[], done=True)

    def trace(self) -> Sequence[TraceEvent]:
        return self._trace

    def close(self) -> None:
        pass


class _MockTarget:
    def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            target_id="mock",
            display_name="Mock",
            description="Mock target",
            version="1.0",
            observability_tier="base",
        )

    def controllables(self) -> Sequence[InterfaceSpec]:
        return [
            InterfaceSpec(
                name="user_input",
                role=InterfaceRole.CONTROLLABLE,
                domains=frozenset({SecurityDomain.USER}),
                description="User input",
            )
        ]

    def observables(self) -> Sequence[InterfaceSpec]:
        return []

    def feedback_channels(self) -> Sequence[InterfaceSpec]:
        return []

    def runtime_params(self) -> Sequence[RuntimeParamSpec]:
        return []

    def open_run(
        self, *, threat_model: ThreatModel, runtime_params: Mapping[str, Any]
    ) -> _MockTargetRun:
        return _MockTargetRun(threat_model)


def test_target_module_satisfies_protocol():
    target = _MockTarget()
    assert isinstance(target, TargetModuleInterface)


def test_target_run_satisfies_protocol():
    tm = ThreatModel(
        allowed_controllables=frozenset(),
        allowed_observables=frozenset(),
        allowed_feedback=frozenset(),
        budget=Budget(),
    )
    run = _MockTargetRun(tm)
    assert isinstance(run, TargetRunInterface)


def test_target_open_run_returns_session():
    target = _MockTarget()
    tm = ThreatModel(
        allowed_controllables=frozenset({"user_input"}),
        allowed_observables=frozenset(),
        allowed_feedback=frozenset(),
        budget=Budget(),
    )
    run = target.open_run(threat_model=tm, runtime_params={})
    result = run.step()
    assert result.done is True
    run.close()


class _MockEvaluatedRun:
    def __init__(self, tm: ThreatModel):
        self._tm = tm

    def threat_model(self) -> ThreatModel:
        return self._tm

    def available_controllables(self) -> Sequence[InterfaceSpec]:
        return []

    def available_observables(self) -> Sequence[InterfaceSpec]:
        return []

    def apply_controllables(self, values: Mapping[str, Any]) -> None:
        pass

    def step(self) -> TurnResult:
        return TurnResult(action=None, observation=None, new_events=[], done=True)

    def latest_feedback(self) -> Optional[TaskFeedback]:
        return TaskFeedback(score=0.0, subscores={}, verdicts=[])

    def trace(self) -> Sequence[TraceEvent]:
        return []

    def close(self) -> None:
        pass


class _MockBound:
    def metadata(self) -> TargetMetadata:
        return TargetMetadata(
            target_id="mock",
            display_name="Mock",
            description="Bound mock",
            version="1.0",
            observability_tier="base",
        )

    def task_definition(self) -> TaskDefinition:
        return TaskDefinition(
            task_id="t1", name="Test", description="desc", adversarial_goal="goal"
        )

    def claims(self) -> Sequence[SecurityClaim]:
        return []

    def open_run(
        self, *, threat_model: ThreatModel, runtime_params: Mapping[str, Any]
    ) -> _MockEvaluatedRun:
        return _MockEvaluatedRun(threat_model)


class _MockTask:
    def task_definition(self) -> TaskDefinition:
        return TaskDefinition(
            task_id="t1", name="Test", description="desc", adversarial_goal="goal"
        )

    def claims(self) -> Sequence[SecurityClaim]:
        return []

    def bind(self, target: TargetModuleInterface) -> _MockBound:
        return _MockBound()


def test_task_module_satisfies_protocol():
    task = _MockTask()
    assert isinstance(task, TaskModuleInterface)


def test_bound_satisfies_protocol():
    bound = _MockBound()
    assert isinstance(bound, BoundTaskTargetInterface)


def test_evaluated_run_satisfies_protocol():
    tm = ThreatModel(
        allowed_controllables=frozenset(),
        allowed_observables=frozenset(),
        allowed_feedback=frozenset(),
        budget=Budget(),
    )
    run = _MockEvaluatedRun(tm)
    assert isinstance(run, EvaluatedRunInterface)


def test_bind_and_run_flow():
    """Full controller-style flow: task.bind(target).open_run().step()."""
    target = _MockTarget()
    task = _MockTask()

    bound = task.bind(target)
    assert bound.task_definition().task_id == "t1"

    tm = ThreatModel(
        allowed_controllables=frozenset({"user_input"}),
        allowed_observables=frozenset(),
        allowed_feedback=frozenset(),
        budget=Budget(),
    )
    run = bound.open_run(threat_model=tm, runtime_params={})
    result = run.step()
    assert result.done is True
    fb = run.latest_feedback()
    assert fb is not None
    assert fb.score == 0.0
    run.close()
