# tests/test_interfaces/test_optimizer_loop.py
import pytest
import asyncio
from superred.interfaces.optimizer import Optimizer
from superred.types import (
    Goal, Event, EventResponse, ControllableInjection, PassThrough,
    ControllablePreCallEvent, ControllableSpec, SecurityDomainTag,
    Trajectory, OptimizerDoneEvent,
)
from superred.types.budget import HierarchicalBudget, Budget
from superred.channels.channel import channel


class InjectingOptimizer(Optimizer):
    async def initialize(self, goal, controllables, observables, budget):
        pass

    async def on_event(self, event):
        if isinstance(event, ControllablePreCallEvent):
            return ControllableInjection(event=event, value="INJECTED")
        return None  # pass-through for other events


class TestRunLoop:
    @pytest.mark.asyncio
    async def test_injection_response(self):
        opt = InjectingOptimizer()
        await opt.initialize(
            Goal(description="test"), [], [],
            HierarchicalBudget(budget=Budget()),
        )
        traj = Trajectory()
        opt._on_run_start(traj)

        event_ch = channel[Event]()
        response_ch = channel[EventResponse]()

        loop_task = asyncio.create_task(
            opt._run_loop(event_ch.receiver, response_ch.sender)
        )

        tag = SecurityDomainTag(name="user")
        spec = ControllableSpec(name="input", security_domain=tag)
        await event_ch.sender.send(
            ControllablePreCallEvent(controllable=spec, request="hello", security_domain=tag)
        )
        resp = await response_ch.receiver.recv()
        assert isinstance(resp, ControllableInjection)
        assert resp.value == "INJECTED"

        # Send a plain event — should get PassThrough
        await event_ch.sender.send(Event())
        resp2 = await response_ch.receiver.recv()
        assert isinstance(resp2, PassThrough)

        event_ch.sender.close()
        await loop_task

    @pytest.mark.asyncio
    async def test_history_tracking(self):
        opt = InjectingOptimizer()
        await opt.initialize(
            Goal(description="test"), [], [],
            HierarchicalBudget(budget=Budget()),
        )
        traj = Trajectory()
        opt._on_run_start(traj)
        assert opt.current_trajectory is traj
        assert len(opt.past_trajectories) == 0

        done = opt._on_run_end()
        assert opt.current_trajectory is None
        assert len(opt.past_trajectories) == 1
