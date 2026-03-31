# tests/test_proxies/test_tool_proxy.py
import pytest
import asyncio

from superred.channels.channel import channel, Channel
from superred.proxies.tool_proxy import tool_proxy
from superred.types.event import (
    Event,
    ControllablePreCallEvent,
    ControllablePostCallEvent,
)
from superred.types.security import SecurityDomainTag
from superred.types.controllable import ControllableSpec
from superred.types.trajectory import Trajectory, TOOL_CALL, TOOL_RESULT


def _make_tag_and_spec():
    tag = SecurityDomainTag(name="tool")
    spec = ControllableSpec(name="bash", security_domain=tag)
    return tag, spec


class TestToolProxy:
    @pytest.mark.asyncio
    async def test_events_pass_through(self):
        """All events should be forwarded unchanged."""
        traj = Trajectory()
        tag, spec = _make_tag_and_spec()

        ch = channel[Event]()
        wrapped = tool_proxy(traj)(ch)

        pre = ControllablePreCallEvent(
            controllable=spec, request="ls -la", security_domain=tag,
        )
        post = ControllablePostCallEvent(
            controllable=spec, request="ls -la", answer="file.txt", security_domain=tag,
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
    async def test_records_tool_call(self):
        """ControllablePreCallEvent should produce a TOOL_CALL trajectory entry."""
        traj = Trajectory()
        tag, spec = _make_tag_and_spec()

        ch = channel[Event]()
        wrapped = tool_proxy(traj)(ch)

        pre = ControllablePreCallEvent(
            controllable=spec, request="run command", security_domain=tag,
        )
        await wrapped.sender.send(pre)
        wrapped.sender.close()

        _ = [item async for item in wrapped.receiver]
        await asyncio.sleep(0.05)

        entries = traj.snapshot()
        assert len(entries) == 1
        assert entries[0].entry_type is TOOL_CALL
        assert entries[0].content == "run command"
        assert entries[0].security_domain is tag

    @pytest.mark.asyncio
    async def test_records_tool_result(self):
        """ControllablePostCallEvent should produce a TOOL_RESULT trajectory entry."""
        traj = Trajectory()
        tag, spec = _make_tag_and_spec()

        ch = channel[Event]()
        wrapped = tool_proxy(traj)(ch)

        post = ControllablePostCallEvent(
            controllable=spec, request="cmd", answer="output", security_domain=tag,
        )
        await wrapped.sender.send(post)
        wrapped.sender.close()

        _ = [item async for item in wrapped.receiver]
        await asyncio.sleep(0.05)

        entries = traj.snapshot()
        assert len(entries) == 1
        assert entries[0].entry_type is TOOL_RESULT
        assert entries[0].content == "output"

    @pytest.mark.asyncio
    async def test_plain_events_not_recorded(self):
        """Plain Event objects should not create trajectory entries."""
        traj = Trajectory()
        ch = channel[Event]()
        wrapped = tool_proxy(traj)(ch)

        await wrapped.sender.send(Event())
        wrapped.sender.close()

        _ = [item async for item in wrapped.receiver]
        await asyncio.sleep(0.05)

        assert len(traj) == 0

    @pytest.mark.asyncio
    async def test_mixed_events_recorded_in_order(self):
        """Pre and post events should produce trajectory entries in order."""
        traj = Trajectory()
        tag, spec = _make_tag_and_spec()

        ch = channel[Event]()
        wrapped = tool_proxy(traj)(ch)

        pre = ControllablePreCallEvent(
            controllable=spec, request="call1", security_domain=tag,
        )
        post = ControllablePostCallEvent(
            controllable=spec, request="call1", answer="result1", security_domain=tag,
        )
        await wrapped.sender.send(pre)
        await wrapped.sender.send(post)
        wrapped.sender.close()

        _ = [item async for item in wrapped.receiver]
        await asyncio.sleep(0.05)

        entries = traj.snapshot()
        assert len(entries) == 2
        assert entries[0].entry_type is TOOL_CALL
        assert entries[1].entry_type is TOOL_RESULT
