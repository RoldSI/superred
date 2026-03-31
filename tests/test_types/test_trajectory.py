# tests/test_types/test_trajectory.py
import pytest
import asyncio
from superred.types.trajectory import (
    Trajectory, TrajectoryEntry, TrajectoryEntryType,
    MODEL_REQUEST, MODEL_RESPONSE, FEEDBACK,
    TOOL_CALL, TOOL_RESULT, INJECTION,
)


class TestTrajectoryEntryType:
    def test_predefined_types(self):
        assert MODEL_REQUEST.name == "model_request"
        assert MODEL_RESPONSE.actor == "llm"
        assert TOOL_CALL.actor == "target"
        assert INJECTION.actor == "optimizer"


class TestTrajectory:
    @pytest.mark.asyncio
    async def test_emit_and_snapshot(self):
        t = Trajectory()
        entry = TrajectoryEntry(entry_type=MODEL_REQUEST, content="hello")
        await t.emit(entry)
        snap = t.snapshot()
        assert len(snap) == 1
        assert snap[0].content == "hello"

    @pytest.mark.asyncio
    async def test_drain_advances_cursor(self):
        t = Trajectory()
        await t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        await t.emit(TrajectoryEntry(entry_type=MODEL_RESPONSE, content="b"))
        batch1 = await t.drain()
        assert len(batch1) == 2
        await t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="c"))
        batch2 = await t.drain()
        assert len(batch2) == 1
        assert batch2[0].content == "c"

    @pytest.mark.asyncio
    async def test_snapshot_does_not_advance_cursor(self):
        t = Trajectory()
        await t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        snap = t.snapshot()
        assert len(snap) == 1
        batch = await t.drain()
        assert len(batch) == 1  # drain still sees it

    @pytest.mark.asyncio
    async def test_emit_after_close_raises(self):
        t = Trajectory()
        t.close()
        with pytest.raises(RuntimeError, match="closed"):
            await t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="x"))

    @pytest.mark.asyncio
    async def test_len(self):
        t = Trajectory()
        assert len(t) == 0
        await t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        assert len(t) == 1

    @pytest.mark.asyncio
    async def test_from_replay(self):
        entries = [
            TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"),
            TrajectoryEntry(entry_type=MODEL_RESPONSE, content="b"),
            TrajectoryEntry(entry_type=TOOL_CALL, content="c"),
        ]
        t = Trajectory.from_replay(entries, replay_until=2)
        snap = t.snapshot()
        assert len(snap) == 2
        assert snap[0].content == "a"
        assert snap[1].content == "b"
