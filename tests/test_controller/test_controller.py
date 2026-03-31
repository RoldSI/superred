"""Tests for the Controller evaluation loop and result types."""

import pytest

from superred.controller.controller import Controller
from superred.controller.results import RunResult, TaskResult, EvalResult
from superred.interfaces.target import Target
from superred.interfaces.task import Task
from superred.interfaces.optimizer import Optimizer
from superred.types import (
    Goal,
    Event,
    EventResponse,
    ControllableInjection,
    ControllablePreCallEvent,
    ControllableSpec,
    Observable,
    ObservableValue,
    ConfigSpec,
    StateSpec,
    RuntimeParamSpec,
    SecurityDomainTag,
    Trajectory,
    EvaluationResult,
    Score,
    OracleBundle,
    OptimizerDoneEvent,
)
from superred.types.security import ThreatModel, Budget
from superred.types.budget import HierarchicalBudget
from superred.channels.channel import AsyncSender, AsyncReceiver


class EmittingTarget(Target):
    """Target that emits one controllable event per run."""

    def __init__(self):
        self._tag = SecurityDomainTag(name="user")
        self._spec = ControllableSpec(name="user_input", security_domain=self._tag)

    def controllable_specs(self):
        return [self._spec]

    def observable_specs(self):
        return []

    def config_specs(self):
        return []

    def state_specs(self):
        return []

    def runtime_params(self):
        return []

    async def set_config(self, name, value):
        pass

    async def get_observables(self):
        return []

    async def get_state(self, name):
        return ""

    async def run(self, send_event, recv_response):
        event = ControllablePreCallEvent(
            controllable=self._spec,
            request="What is 2+2?",
            security_domain=self._tag,
        )
        await send_event.send(event)
        response = await recv_response.recv()
        # Target processes the response (in real target, would use injection value)


class AlwaysSuccessTask(Task[EmittingTarget]):
    @property
    def goal(self):
        return Goal(description="Test goal")

    async def configure(self, target):
        return {"setup": "done"}

    async def evaluate(self, trajectory, target):
        return EvaluationResult(success=True, primary_score=Score(value=1.0))

    def oracle_bundle(self):
        return OracleBundle()


class InjectOptimizer(Optimizer):
    def __init__(self):
        super().__init__()
        self._call_count = 0
        self._max_calls = 2

    async def initialize(self, goal, controllables, observables, budget):
        pass

    async def on_event(self, event):
        if isinstance(event, ControllablePreCallEvent):
            return ControllableInjection(event=event, value="INJECTED")
        return None

    async def post_run(self):
        self._call_count += 1
        if self._call_count >= self._max_calls:
            return OptimizerDoneEvent()
        return None


class TestController:
    @pytest.mark.asyncio
    async def test_single_run(self):
        target = EmittingTarget()
        task = AlwaysSuccessTask()
        optimizer = InjectOptimizer()
        optimizer._max_calls = 1  # stop after 1 run

        tm = ThreatModel(
            name="user_only",
            controllables=frozenset({"user_input"}),
            observables=frozenset(),
            feedback=frozenset(),
            budget=Budget(max_iterations=5),
        )
        budget = HierarchicalBudget(budget=Budget(max_iterations=5))

        controller = Controller(target, task, optimizer, tm, budget)
        result = await controller.run()

        assert isinstance(result, TaskResult)
        assert len(result.runs) >= 1
        assert result.runs[0].evaluation.success is True
        assert result.runs[0].evaluation.primary_score.value == 1.0

    @pytest.mark.asyncio
    async def test_budget_stops_loop(self):
        target = EmittingTarget()
        task = AlwaysSuccessTask()
        optimizer = InjectOptimizer()
        optimizer._max_calls = 100  # optimizer won't stop on its own

        tm = ThreatModel(
            name="user_only",
            controllables=frozenset({"user_input"}),
            observables=frozenset(),
            feedback=frozenset(),
            budget=Budget(max_iterations=3),
        )
        budget = HierarchicalBudget(budget=Budget(max_iterations=3))

        controller = Controller(target, task, optimizer, tm, budget)
        result = await controller.run()

        assert len(result.runs) == 3

    @pytest.mark.asyncio
    async def test_optimizer_done_stops_loop(self):
        target = EmittingTarget()
        task = AlwaysSuccessTask()
        optimizer = InjectOptimizer()
        optimizer._max_calls = 2  # stops after 2

        tm = ThreatModel(
            name="user_only",
            controllables=frozenset({"user_input"}),
            observables=frozenset(),
            feedback=frozenset(),
            budget=Budget(max_iterations=10),
        )
        budget = HierarchicalBudget(budget=Budget(max_iterations=10))

        controller = Controller(target, task, optimizer, tm, budget)
        result = await controller.run()

        assert len(result.runs) == 2


class TestResults:
    def test_eval_result_asr(self):
        s_pass = Score(value=1.0)
        s_fail = Score(value=0.0)
        r1 = RunResult(
            trajectory=Trajectory(),
            evaluation=EvaluationResult(success=True, primary_score=s_pass),
        )
        r2 = RunResult(
            trajectory=Trajectory(),
            evaluation=EvaluationResult(success=False, primary_score=s_fail),
        )
        tr = TaskResult(task_goal=Goal(description="test"), runs=[r1, r2])
        er = EvalResult(task_results={"user_only": [tr]})
        asr = er.asr_by_threat_model()
        assert asr["user_only"] == 0.5

    def test_best_run(self):
        s1 = Score(value=0.3)
        s2 = Score(value=0.9)
        r1 = RunResult(
            trajectory=Trajectory(),
            evaluation=EvaluationResult(success=False, primary_score=s1),
        )
        r2 = RunResult(
            trajectory=Trajectory(),
            evaluation=EvaluationResult(success=True, primary_score=s2),
        )
        tr = TaskResult(task_goal=Goal(description="test"), runs=[r1, r2])
        assert tr.best_run is r2
