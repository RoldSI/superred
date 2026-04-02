"""Unit tests for Trajectory, TrajectoryEntry, and TrajectoryEntryType."""

from __future__ import annotations

import threading
from datetime import datetime

import pytest

from superred.core.types.evaluation import FeedbackResult
from superred.core.types.trajectory import (
    DEFAULT_ENTRY_TYPES,
    FEEDBACK,
    MODEL_REQUEST,
    MODEL_RESPONSE,
    Trajectory,
    TrajectoryEntry,
    TrajectoryEntryType,
)

# ---------------------------------------------------------------------------
# TrajectoryEntryType
# ---------------------------------------------------------------------------


class TestTrajectoryEntryType:
    def test_default_types_exist(self) -> None:
        assert MODEL_REQUEST.name == "model_request"
        assert MODEL_REQUEST.content_type is str
        assert MODEL_RESPONSE.name == "model_response"
        assert MODEL_RESPONSE.content_type is str
        assert FEEDBACK.name == "feedback"
        assert FEEDBACK.content_type is FeedbackResult

    def test_default_set_has_three(self) -> None:
        assert len(DEFAULT_ENTRY_TYPES) == 3

    def test_custom_type(self) -> None:
        custom = TrajectoryEntryType(
            name="tool_call",
            description="A tool invocation",
            actor="AI system",
            content_type=dict,
        )
        assert custom.name == "tool_call"
        assert custom.content_type is dict


# ---------------------------------------------------------------------------
# TrajectoryEntry
# ---------------------------------------------------------------------------


class TestTrajectoryEntry:
    def test_construction(self) -> None:
        entry = TrajectoryEntry(entry_type=MODEL_REQUEST, content="Hello")
        assert entry.entry_type is MODEL_REQUEST
        assert entry.content == "Hello"
        assert isinstance(entry.timestamp, datetime)

    def test_mutable(self) -> None:
        """TrajectoryEntry is a mutable dataclass."""
        entry = TrajectoryEntry(entry_type=MODEL_REQUEST, content="a")
        entry.content = "b"
        assert entry.content == "b"


# ---------------------------------------------------------------------------
# Trajectory
# ---------------------------------------------------------------------------


class TestTrajectory:
    def test_empty_trajectory(self) -> None:
        t = Trajectory()
        assert t.snapshot() == []
        assert t.drain() == []

    def test_emit_and_snapshot(self) -> None:
        t = Trajectory()
        entry = TrajectoryEntry(entry_type=MODEL_REQUEST, content="Hello")
        t.emit(entry)
        snap = t.snapshot()
        assert len(snap) == 1
        assert snap[0] is entry

    def test_emit_after_close_raises(self) -> None:
        t = Trajectory()
        t.close()
        with pytest.raises(RuntimeError, match="closed"):
            t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="x"))

    def test_snapshot_does_not_advance_cursor(self) -> None:
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        t.snapshot()
        # drain should still see the entry
        drained = t.drain()
        assert len(drained) == 1

    def test_drain_returns_new_entries_only(self) -> None:
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        first = t.drain()
        assert len(first) == 1

        # No new entries
        assert t.drain() == []

        # Add another
        t.emit(TrajectoryEntry(entry_type=MODEL_RESPONSE, content="b"))
        second = t.drain()
        assert len(second) == 1
        assert second[0].content == "b"

    def test_drain_returns_all_new_since_last_drain(self) -> None:
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="1"))
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="2"))
        t.drain()  # advance cursor past both
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="3"))
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="4"))
        drained = t.drain()
        assert [e.content for e in drained] == ["3", "4"]

    def test_snapshot_grows_with_emits(self) -> None:
        t = Trajectory()
        assert len(t.snapshot()) == 0
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        assert len(t.snapshot()) == 1
        t.emit(TrajectoryEntry(entry_type=MODEL_RESPONSE, content="b"))
        assert len(t.snapshot()) == 2

    def test_close_idempotent(self) -> None:
        t = Trajectory()
        t.close()
        t.close()  # should not raise
        # Still closed — emit should still fail
        with pytest.raises(RuntimeError, match="closed"):
            t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="x"))

    def test_snapshot_returns_copy(self) -> None:
        """Mutating snapshot list does not affect trajectory."""
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        snap = t.snapshot()
        snap.clear()
        assert len(t.snapshot()) == 1

    def test_custom_entry_types(self) -> None:
        custom = TrajectoryEntryType(
            name="tool",
            description="Tool call",
            actor="AI system",
            content_type=dict,
        )
        t = Trajectory(entry_types=[custom])
        # Default types are always present
        assert MODEL_REQUEST in t._entry_types
        assert custom in t._entry_types

    def test_emit_accepts_unregistered_entry_type(self) -> None:
        """emit() does not validate entry types against _entry_types.

        Trajectory._entry_types is stored at construction but never checked
        during emit(). This test documents the current behavior — emit
        accepts any TrajectoryEntryType, even one not registered.
        """
        unregistered = TrajectoryEntryType(
            name="unregistered",
            description="Not in _entry_types",
            actor="test",
            content_type=str,
        )
        t = Trajectory()  # only default types registered
        assert unregistered not in t._entry_types
        # emit succeeds anyway — no validation
        t.emit(TrajectoryEntry(entry_type=unregistered, content="hello"))
        assert len(t.snapshot()) == 1

    def test_thread_safety_emit(self) -> None:
        """Multiple threads can emit concurrently without data loss."""
        t = Trajectory()
        n_threads = 10
        n_per_thread = 100
        barrier = threading.Barrier(n_threads)

        def emitter() -> None:
            barrier.wait()
            for i in range(n_per_thread):
                t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content=str(i)))

        threads = [threading.Thread(target=emitter) for _ in range(n_threads)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert len(t.snapshot()) == n_threads * n_per_thread

    def test_snapshot_after_close(self) -> None:
        """snapshot() still works correctly after close()."""
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        t.emit(TrajectoryEntry(entry_type=MODEL_RESPONSE, content="b"))
        t.close()
        snap = t.snapshot()
        assert len(snap) == 2
        assert snap[0].content == "a"
        assert snap[1].content == "b"

    def test_drain_after_close(self) -> None:
        """drain() still works correctly after close()."""
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        t.close()
        drained = t.drain()
        assert len(drained) == 1
        assert drained[0].content == "a"
        # Second drain returns nothing
        assert t.drain() == []

    def test_drain_returns_copy(self) -> None:
        """Mutating the drained list does not affect the trajectory."""
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a"))
        drained = t.drain()
        drained.clear()
        # snapshot should still have the entry
        assert len(t.snapshot()) == 1
