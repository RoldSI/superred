# tests/test_interfaces/test_abcs.py
import pytest
from superred.interfaces.target import Target
from superred.interfaces.task import Task, NotApplicable
from superred.interfaces.optimizer import Optimizer
from superred.interfaces.judge import Judge
from superred.interfaces.security_claim import SecurityClaim
from superred.types import (
    Goal, Event, EventResponse, PassThrough, ControllableSpec, Controllable,
    Observable, ObservableValue, ConfigSpec, StateSpec, RuntimeParamSpec,
    Trajectory, TrajectoryEntry, MODEL_REQUEST, EvaluationResult, Score,
    OracleBundle, SecurityDomainTag, OptimizerDoneEvent,
)
from superred.types.budget import HierarchicalBudget, Budget
from superred.channels.channel import AsyncSender, AsyncReceiver


class StubTarget(Target):
    def controllable_specs(self): return []
    def observable_specs(self): return []
    def config_specs(self): return []
    def state_specs(self): return []
    def runtime_params(self): return []
    async def set_config(self, name, value): pass
    async def get_observables(self): return []
    async def run(self, send_event, recv_response): pass
    async def get_state(self, name): return ""


class StubTask(Task[StubTarget]):
    @property
    def goal(self): return Goal(description="test")
    async def configure(self, target): return {}
    async def evaluate(self, trajectory, target):
        return EvaluationResult(success=False, primary_score=Score(value=0.0))
    def oracle_bundle(self): return OracleBundle()


class StubOptimizer(Optimizer):
    async def initialize(self, goal, controllables, observables, budget): pass
    async def on_event(self, event): return None


class StubJudge(Judge):
    async def evaluate(self, goal, trajectory, oracle):
        return EvaluationResult(success=True, primary_score=Score(value=1.0))


class TestTarget:
    def test_instantiate(self):
        t = StubTarget()
        assert t.max_concurrent_runs == 1

    @pytest.mark.asyncio
    async def test_lifecycle(self):
        t = StubTarget()
        await t.setup()
        await t.teardown()


class TestTask:
    def test_goal(self):
        task = StubTask()
        assert task.goal.description == "test"

    def test_not_applicable(self):
        with pytest.raises(NotApplicable):
            raise NotApplicable("incompatible target")


class TestOptimizer:
    @pytest.mark.asyncio
    async def test_initialize(self):
        opt = StubOptimizer()
        await opt.initialize(
            Goal(description="test"), [], [],
            HierarchicalBudget(budget=Budget()),
        )

    @pytest.mark.asyncio
    async def test_on_event_returns_none(self):
        opt = StubOptimizer()
        resp = await opt.on_event(Event())
        assert resp is None

    def test_history_tracking(self):
        opt = StubOptimizer()
        assert opt.current_trajectory is None
        assert opt.past_trajectories == []
        traj = Trajectory()
        opt._on_run_start(traj)
        assert opt.current_trajectory is traj
        done = opt._on_run_end()
        assert opt.current_trajectory is None
        assert len(opt.past_trajectories) == 1

    @pytest.mark.asyncio
    async def test_teardown(self):
        opt = StubOptimizer()
        await opt.teardown()  # should not raise

    def test_metadata(self):
        opt = StubOptimizer()
        meta = opt.get_metadata()
        assert isinstance(meta, dict)


class TestJudge:
    @pytest.mark.asyncio
    async def test_evaluate(self):
        judge = StubJudge()
        result = await judge.evaluate(
            Goal(description="test"), Trajectory(), OracleBundle()
        )
        assert result.success is True


class TestSecurityClaim:
    def test_from_tasks_iterable(self):
        t1 = StubTask()
        t2 = StubTask()
        claim = SecurityClaim.from_tasks([t1, t2])
        tasks = list(claim)
        assert len(tasks) == 2

    def test_from_claims_lazy_chain(self):
        c1 = SecurityClaim.from_tasks([StubTask()])
        c2 = SecurityClaim.from_tasks([StubTask(), StubTask()])
        combined = SecurityClaim.from_claims([c1, c2])
        assert len(list(combined)) == 3

    def test_re_iterable(self):
        claim = SecurityClaim.from_tasks([StubTask()])
        assert len(list(claim)) == len(list(claim))
