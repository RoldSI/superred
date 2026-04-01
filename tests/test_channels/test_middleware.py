# tests/test_channels/test_middleware.py
import pytest
import asyncio
from superred.channels.channel import channel, Channel
from superred.channels.middleware import (
    Middleware, compose, trace_recorder, threat_model_filter, budget_enforcer, logger_middleware,
)
from superred.types.event import Event, ControllablePreCallEvent
from superred.types.security import SecurityDomainTag, ThreatModel, Budget
from superred.types.controllable import ControllableSpec
from superred.types.trajectory import Trajectory
from superred.types.budget import HierarchicalBudget


class TestCompose:
    @pytest.mark.asyncio
    async def test_identity(self):
        """No middleware = pass-through."""
        ch = channel[str]()
        composed = compose()(ch)
        await composed.sender.send("hello")
        composed.sender.close()
        items = [item async for item in composed.receiver]
        assert items == ["hello"]


class TestTraceRecorder:
    @pytest.mark.asyncio
    async def test_records_events(self):
        traj = Trajectory()
        ch = channel[Event]()
        wrapped = trace_recorder(traj)(ch)

        tag = SecurityDomainTag(name="user")
        spec = ControllableSpec(name="input", security_domain=tag)
        event = ControllablePreCallEvent(
            controllable=spec, request="test", security_domain=tag,
        )
        await wrapped.sender.send(event)
        wrapped.sender.close()

        _ = [item async for item in wrapped.receiver]  # drain receiver
        await asyncio.sleep(0.05)  # give recorder task time to process
        assert len(traj) >= 1


class TestThreatModelFilter:
    @pytest.mark.asyncio
    async def test_passes_allowed_domain(self):
        tm = ThreatModel(
            name="user_only",
            controllables=frozenset({"user"}),
            observables=frozenset(),
            feedback=frozenset(),
            budget=Budget(),
        )
        ch = channel[Event]()
        wrapped = threat_model_filter(tm)(ch)

        tag = SecurityDomainTag(name="user")
        event = Event(security_domain=tag)
        await wrapped.sender.send(event)
        wrapped.sender.close()

        items = [item async for item in wrapped.receiver]
        assert len(items) == 1

    @pytest.mark.asyncio
    async def test_drops_disallowed_domain(self):
        tm = ThreatModel(
            name="user_only",
            controllables=frozenset({"user_input"}),
            observables=frozenset(),
            feedback=frozenset(),
            budget=Budget(),
        )
        ch = channel[Event]()
        wrapped = threat_model_filter(tm)(ch)

        tag = SecurityDomainTag(name="internal")
        event = Event(security_domain=tag)
        await wrapped.sender.send(event)
        wrapped.sender.close()

        items = [item async for item in wrapped.receiver]
        assert len(items) == 0

    @pytest.mark.asyncio
    async def test_passes_events_without_domain(self):
        """Events with no security_domain should always pass through."""
        tm = ThreatModel(
            name="strict",
            controllables=frozenset(),
            observables=frozenset(),
            feedback=frozenset(),
            budget=Budget(),
        )
        ch = channel[Event]()
        wrapped = threat_model_filter(tm)(ch)

        event = Event()  # no security_domain
        await wrapped.sender.send(event)
        wrapped.sender.close()

        items = [item async for item in wrapped.receiver]
        assert len(items) == 1


class TestBudgetEnforcer:
    @pytest.mark.asyncio
    async def test_closes_on_exhaustion(self):
        hb = HierarchicalBudget(budget=Budget(max_iterations=2))
        ch = channel[Event]()
        wrapped = budget_enforcer(hb)(ch)

        for _ in range(3):
            await wrapped.sender.send(Event())

        wrapped.sender.close()
        items = [item async for item in wrapped.receiver]
        assert len(items) <= 2
