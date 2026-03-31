# tests/test_proxies/test_replay.py
import pytest
import asyncio

from superred.channels.channel import channel, Channel
from superred.proxies.replay import replay_proxy, ReplayDivergenceError
from superred.types.event import (
    Event,
    EventResponse,
    ControllablePreCallEvent,
    ControllablePostCallEvent,
    PassThrough,
)
from superred.types.security import SecurityDomainTag
from superred.types.controllable import ControllableSpec
from superred.types.trajectory import TrajectoryEntry, MODEL_REQUEST, MODEL_RESPONSE


def _make_tag_and_spec():
    tag = SecurityDomainTag(name="llm")
    spec = ControllableSpec(name="model", security_domain=tag)
    return tag, spec


def _make_entry(entry_type, content, tag):
    return TrajectoryEntry(
        entry_type=entry_type, content=content, security_domain=tag,
    )


class TestReplayProxy:
    @pytest.mark.asyncio
    async def test_events_before_checkpoint_get_recorded_responses(self):
        """Events with index < checkpoint should get recorded responses."""
        tag, spec = _make_tag_and_spec()

        event0 = ControllablePreCallEvent(
            controllable=spec, request="q0", security_domain=tag,
        )
        event1 = ControllablePreCallEvent(
            controllable=spec, request="q1", security_domain=tag,
        )
        resp0 = PassThrough(event=event0)
        resp1 = PassThrough(event=event1)

        entries = [
            _make_entry(MODEL_REQUEST, "q0", tag),
            _make_entry(MODEL_REQUEST, "q1", tag),
        ]

        ch = channel[Event]()
        wrapped = replay_proxy(entries, [resp0, resp1], checkpoint=2)(ch)

        await wrapped.sender.send(event0)
        await wrapped.sender.send(event1)
        wrapped.sender.close()

        items = [item async for item in wrapped.receiver]
        # Events before checkpoint return recorded responses, not the live events
        assert len(items) == 2
        assert items[0] is resp0
        assert items[1] is resp1

    @pytest.mark.asyncio
    async def test_events_at_and_after_checkpoint_flow_through_live(self):
        """Events with index >= checkpoint should pass through live."""
        tag, spec = _make_tag_and_spec()

        event0 = ControllablePreCallEvent(
            controllable=spec, request="q0", security_domain=tag,
        )
        event1 = ControllablePreCallEvent(
            controllable=spec, request="q1", security_domain=tag,
        )
        resp0 = PassThrough(event=event0)

        entries = [_make_entry(MODEL_REQUEST, "q0", tag)]

        ch = channel[Event]()
        wrapped = replay_proxy(entries, [resp0], checkpoint=1)(ch)

        await wrapped.sender.send(event0)
        await wrapped.sender.send(event1)
        wrapped.sender.close()

        items = [item async for item in wrapped.receiver]
        assert len(items) == 2
        # First event (index 0 < checkpoint 1) gets recorded response
        assert items[0] is resp0
        # Second event (index 1 >= checkpoint 1) flows through live
        assert items[1] is event1

    @pytest.mark.asyncio
    async def test_checkpoint_zero_all_events_live(self):
        """With checkpoint=0, all events flow through live."""
        tag, spec = _make_tag_and_spec()

        event = ControllablePreCallEvent(
            controllable=spec, request="q", security_domain=tag,
        )

        ch = channel[Event]()
        wrapped = replay_proxy([], [], checkpoint=0)(ch)

        await wrapped.sender.send(event)
        wrapped.sender.close()

        items = [item async for item in wrapped.receiver]
        assert len(items) == 1
        assert items[0] is event

    @pytest.mark.asyncio
    async def test_divergence_error_on_impossible_checkpoint(self):
        """Checkpoint beyond recorded entries should raise ReplayDivergenceError."""
        # Only 1 recorded entry but checkpoint says replay 5
        tag, spec = _make_tag_and_spec()
        entries = [_make_entry(MODEL_REQUEST, "q0", tag)]
        responses = [PassThrough(event=Event())]

        ch = channel[Event]()

        with pytest.raises(ReplayDivergenceError) as exc_info:
            replay_proxy(entries, responses, checkpoint=5)(ch)

        assert exc_info.value.checkpoint == 5

    @pytest.mark.asyncio
    async def test_empty_replay(self):
        """Empty recorded entries with checkpoint=0 should work normally."""
        ch = channel[Event]()
        wrapped = replay_proxy([], [], checkpoint=0)(ch)

        event = Event()
        await wrapped.sender.send(event)
        wrapped.sender.close()

        items = [item async for item in wrapped.receiver]
        assert len(items) == 1
        assert items[0] is event


class TestStagedRunner:
    """Basic tests for the StagedRunner class."""

    def test_import(self):
        """StagedRunner should be importable."""
        from superred.controller.stage import StagedRunner
        runner = StagedRunner()
        assert runner is not None
