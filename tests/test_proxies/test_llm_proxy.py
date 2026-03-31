# tests/test_proxies/test_llm_proxy.py
import pytest
import asyncio

from superred.channels.channel import channel, Channel
from superred.proxies.llm_proxy import llm_proxy
from superred.types.event import (
    Event,
    ControllablePreCallEvent,
    ControllablePostCallEvent,
)
from superred.types.security import SecurityDomainTag, Budget
from superred.types.controllable import ControllableSpec
from superred.types.trajectory import Trajectory, MODEL_REQUEST, MODEL_RESPONSE
from superred.types.budget import HierarchicalBudget


def _make_tag_and_spec():
    tag = SecurityDomainTag(name="llm")
    spec = ControllableSpec(name="model_call", security_domain=tag)
    return tag, spec


class TestLlmProxy:
    @pytest.mark.asyncio
    async def test_events_pass_through(self):
        """All events should be forwarded unchanged."""
        traj = Trajectory()
        tag, spec = _make_tag_and_spec()

        ch = channel[Event]()
        wrapped = llm_proxy(traj)(ch)

        pre = ControllablePreCallEvent(
            controllable=spec, request="hello", security_domain=tag,
        )
        post = ControllablePostCallEvent(
            controllable=spec, request="hello", answer="world", security_domain=tag,
        )
        plain = Event(security_domain=tag)

        await wrapped.sender.send(pre)
        await wrapped.sender.send(post)
        await wrapped.sender.send(plain)
        wrapped.sender.close()

        items = [item async for item in wrapped.receiver]
        assert len(items) == 3
        assert items[0] is pre
        assert items[1] is post
        assert items[2] is plain

    @pytest.mark.asyncio
    async def test_records_model_request(self):
        """ControllablePreCallEvent should produce a MODEL_REQUEST trajectory entry."""
        traj = Trajectory()
        tag, spec = _make_tag_and_spec()

        ch = channel[Event]()
        wrapped = llm_proxy(traj)(ch)

        pre = ControllablePreCallEvent(
            controllable=spec, request="prompt text", security_domain=tag,
        )
        await wrapped.sender.send(pre)
        wrapped.sender.close()

        _ = [item async for item in wrapped.receiver]
        await asyncio.sleep(0.05)

        entries = traj.snapshot()
        assert len(entries) == 1
        assert entries[0].entry_type is MODEL_REQUEST
        assert entries[0].content == "prompt text"
        assert entries[0].security_domain is tag

    @pytest.mark.asyncio
    async def test_records_model_response(self):
        """ControllablePostCallEvent should produce a MODEL_RESPONSE trajectory entry."""
        traj = Trajectory()
        tag, spec = _make_tag_and_spec()

        ch = channel[Event]()
        wrapped = llm_proxy(traj)(ch)

        post = ControllablePostCallEvent(
            controllable=spec, request="prompt", answer="reply", security_domain=tag,
        )
        await wrapped.sender.send(post)
        wrapped.sender.close()

        _ = [item async for item in wrapped.receiver]
        await asyncio.sleep(0.05)

        entries = traj.snapshot()
        assert len(entries) == 1
        assert entries[0].entry_type is MODEL_RESPONSE
        assert entries[0].content == "reply"

    @pytest.mark.asyncio
    async def test_plain_events_not_recorded(self):
        """Plain Event objects should not create trajectory entries."""
        traj = Trajectory()
        ch = channel[Event]()
        wrapped = llm_proxy(traj)(ch)

        await wrapped.sender.send(Event())
        wrapped.sender.close()

        _ = [item async for item in wrapped.receiver]
        await asyncio.sleep(0.05)

        assert len(traj) == 0

    @pytest.mark.asyncio
    async def test_budget_tracking(self):
        """When budget is provided, model_calls should be incremented on post-call events."""
        traj = Trajectory()
        budget = HierarchicalBudget(budget=Budget(max_model_calls=10))
        tag, spec = _make_tag_and_spec()

        ch = channel[Event]()
        wrapped = llm_proxy(traj, budget=budget)(ch)

        post = ControllablePostCallEvent(
            controllable=spec, request="q", answer="a", security_domain=tag,
        )
        await wrapped.sender.send(post)
        await wrapped.sender.send(post)
        wrapped.sender.close()

        _ = [item async for item in wrapped.receiver]
        await asyncio.sleep(0.05)

        assert budget.usage.model_calls == 2

    @pytest.mark.asyncio
    async def test_no_budget_no_crash(self):
        """With budget=None, post-call events should not raise."""
        traj = Trajectory()
        tag, spec = _make_tag_and_spec()

        ch = channel[Event]()
        wrapped = llm_proxy(traj, budget=None)(ch)

        post = ControllablePostCallEvent(
            controllable=spec, request="q", answer="a", security_domain=tag,
        )
        await wrapped.sender.send(post)
        wrapped.sender.close()

        items = [item async for item in wrapped.receiver]
        assert len(items) == 1
