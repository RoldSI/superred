"""Unit tests for Trajectory, TrajectoryEntry, TrajectoryEntryType, and FilteredTrajectory."""

from __future__ import annotations

import threading
from datetime import datetime

import pytest

from superred.core.types.evaluation import FeedbackResult
from superred.core.types.security_domain import SecurityDomainTag
from superred.core.types.trajectory import (
    DEFAULT_ENTRY_TYPES,
    FEEDBACK,
    MODEL_REQUEST,
    MODEL_RESPONSE,
    Trajectory,
    TrajectoryEntry,
    TrajectoryEntryType,
)

# Reusable tags for trajectory tests
_TAG = SecurityDomainTag("test")
_PARENT = SecurityDomainTag("parent")
_CHILD = SecurityDomainTag("child", parent=_PARENT)
_SIBLING = SecurityDomainTag("sibling", parent=_PARENT)

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
        entry = TrajectoryEntry(entry_type=MODEL_REQUEST, content="Hello", security_domain=_TAG)
        assert entry.entry_type is MODEL_REQUEST
        assert entry.content == "Hello"
        assert entry.security_domain is _TAG
        assert isinstance(entry.timestamp, datetime)

    def test_security_domain_is_required(self) -> None:
        """security_domain has no default — must be provided."""
        with pytest.raises(TypeError):
            TrajectoryEntry(entry_type=MODEL_REQUEST, content="x")  # type: ignore[call-arg]

    def test_mutable(self) -> None:
        """TrajectoryEntry is a mutable dataclass."""
        entry = TrajectoryEntry(entry_type=MODEL_REQUEST, content="a", security_domain=_TAG)
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
        entry = TrajectoryEntry(entry_type=MODEL_REQUEST, content="Hello", security_domain=_TAG)
        t.emit(entry)
        snap = t.snapshot()
        assert len(snap) == 1
        assert snap[0] is entry

    def test_emit_after_close_raises(self) -> None:
        t = Trajectory()
        t.close()
        with pytest.raises(RuntimeError, match="closed"):
            t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="x", security_domain=_TAG))

    def test_snapshot_does_not_advance_cursor(self) -> None:
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a", security_domain=_TAG))
        t.snapshot()
        # drain should still see the entry
        drained = t.drain()
        assert len(drained) == 1

    def test_drain_returns_new_entries_only(self) -> None:
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a", security_domain=_TAG))
        first = t.drain()
        assert len(first) == 1

        # No new entries
        assert t.drain() == []

        # Add another
        t.emit(TrajectoryEntry(entry_type=MODEL_RESPONSE, content="b", security_domain=_TAG))
        second = t.drain()
        assert len(second) == 1
        assert second[0].content == "b"

    def test_drain_returns_all_new_since_last_drain(self) -> None:
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="1", security_domain=_TAG))
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="2", security_domain=_TAG))
        t.drain()  # advance cursor past both
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="3", security_domain=_TAG))
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="4", security_domain=_TAG))
        drained = t.drain()
        assert [e.content for e in drained] == ["3", "4"]

    def test_snapshot_grows_with_emits(self) -> None:
        t = Trajectory()
        assert len(t.snapshot()) == 0
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a", security_domain=_TAG))
        assert len(t.snapshot()) == 1
        t.emit(TrajectoryEntry(entry_type=MODEL_RESPONSE, content="b", security_domain=_TAG))
        assert len(t.snapshot()) == 2

    def test_close_idempotent(self) -> None:
        t = Trajectory()
        t.close()
        t.close()  # should not raise
        # Still closed — emit should still fail
        with pytest.raises(RuntimeError, match="closed"):
            t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="x", security_domain=_TAG))

    def test_snapshot_returns_copy(self) -> None:
        """Mutating snapshot list does not affect trajectory."""
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a", security_domain=_TAG))
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
        t.emit(TrajectoryEntry(entry_type=unregistered, content="hello", security_domain=_TAG))
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
                t.emit(TrajectoryEntry(
                    entry_type=MODEL_REQUEST, content=str(i), security_domain=_TAG,
                ))

        threads = [threading.Thread(target=emitter) for _ in range(n_threads)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        assert len(t.snapshot()) == n_threads * n_per_thread

    def test_snapshot_after_close(self) -> None:
        """snapshot() still works correctly after close()."""
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a", security_domain=_TAG))
        t.emit(TrajectoryEntry(entry_type=MODEL_RESPONSE, content="b", security_domain=_TAG))
        t.close()
        snap = t.snapshot()
        assert len(snap) == 2
        assert snap[0].content == "a"
        assert snap[1].content == "b"

    def test_drain_after_close(self) -> None:
        """drain() still works correctly after close()."""
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a", security_domain=_TAG))
        t.close()
        drained = t.drain()
        assert len(drained) == 1
        assert drained[0].content == "a"
        # Second drain returns nothing
        assert t.drain() == []

    def test_drain_returns_copy(self) -> None:
        """Mutating the drained list does not affect the trajectory."""
        t = Trajectory()
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a", security_domain=_TAG))
        drained = t.drain()
        drained.clear()
        # snapshot should still have the entry
        assert len(t.snapshot()) == 1


# ---------------------------------------------------------------------------
# FilteredTrajectory
# ---------------------------------------------------------------------------


class TestFilteredTrajectory:
    def test_snapshot_filters_by_scope(self) -> None:
        t = Trajectory(filtered_scope=_CHILD)
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="child", security_domain=_CHILD))
        t.emit(TrajectoryEntry(
            entry_type=MODEL_REQUEST, content="sibling", security_domain=_SIBLING,
        ))
        snap = t.filtered.snapshot()
        assert len(snap) == 1
        assert snap[0].content == "child"

    def test_snapshot_includes_descendants(self) -> None:
        t = Trajectory(filtered_scope=_PARENT)
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="child", security_domain=_CHILD))
        t.emit(TrajectoryEntry(
            entry_type=MODEL_REQUEST, content="sibling", security_domain=_SIBLING,
        ))
        assert len(t.filtered.snapshot()) == 2

    def test_snapshot_empty_when_nothing_in_scope(self) -> None:
        t = Trajectory(filtered_scope=_CHILD)
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="x", security_domain=_SIBLING))
        assert t.filtered.snapshot() == []

    def test_drain_returns_new_in_scope_entries(self) -> None:
        t = Trajectory(filtered_scope=_CHILD)
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a", security_domain=_CHILD))
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="b", security_domain=_SIBLING))

        first = t.filtered.drain()
        assert len(first) == 1
        assert first[0].content == "a"

        # No new entries
        assert t.filtered.drain() == []

        # Add more entries — only in-scope ones returned
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="c", security_domain=_CHILD))
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="d", security_domain=_SIBLING))
        second = t.filtered.drain()
        assert len(second) == 1
        assert second[0].content == "c"

    def test_drain_cursor_independent_of_underlying(self) -> None:
        """FilteredTrajectory's drain cursor is independent of Trajectory's."""
        t = Trajectory(filtered_scope=_CHILD)
        t.emit(TrajectoryEntry(entry_type=MODEL_REQUEST, content="a", security_domain=_CHILD))

        # Drain the underlying trajectory
        t.drain()
        # FilteredTrajectory should still see the entry on its first drain
        assert len(t.filtered.drain()) == 1

    def test_no_emit_or_close(self) -> None:
        """FilteredTrajectory is read-only — no emit() or close()."""
        t = Trajectory(filtered_scope=_TAG)
        assert not hasattr(t.filtered, "emit")
        assert not hasattr(t.filtered, "close")

    def test_no_trajectory_reference(self) -> None:
        """FilteredTrajectory holds no reference to the underlying Trajectory."""
        t = Trajectory(filtered_scope=_TAG)
        filtered = t.filtered
        for attr in dir(filtered):
            val = getattr(filtered, attr)
            assert not isinstance(val, Trajectory), (
                f"attribute {attr!r} references the underlying Trajectory"
            )
        # No __dict__ (slots-only)
        assert not hasattr(filtered, "__dict__")

    def test_thread_safety(self) -> None:
        """Concurrent drain() calls on FilteredTrajectory are safe."""
        t = Trajectory(filtered_scope=_CHILD)
        for i in range(100):
            t.emit(TrajectoryEntry(
                entry_type=MODEL_REQUEST, content=str(i), security_domain=_CHILD,
            ))
        results: list[list[TrajectoryEntry]] = []
        lock = threading.Lock()

        def drainer() -> None:
            drained = t.filtered.drain()
            with lock:
                results.append(drained)

        threads = [threading.Thread(target=drainer) for _ in range(5)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        total = sum(len(r) for r in results)
        assert total == 100

    def test_empty_trajectory(self) -> None:
        """FilteredTrajectory on an empty trajectory returns empty results."""
        t = Trajectory(filtered_scope=_CHILD)
        assert t.filtered.snapshot() == []
        assert t.filtered.drain() == []

    def test_scope_matches_everything(self) -> None:
        """Parent scope includes all descendants."""
        t = Trajectory(filtered_scope=_PARENT)
        t.emit(TrajectoryEntry(
            entry_type=MODEL_REQUEST, content="child", security_domain=_CHILD,
        ))
        t.emit(TrajectoryEntry(
            entry_type=MODEL_REQUEST, content="sibling", security_domain=_SIBLING,
        ))
        t.emit(TrajectoryEntry(
            entry_type=MODEL_REQUEST, content="parent", security_domain=_PARENT,
        ))
        assert len(t.filtered.snapshot()) == 3

    def test_live_updates_visible(self) -> None:
        """Entries emitted after construction are pushed to filtered view."""
        t = Trajectory(filtered_scope=_CHILD)
        assert t.filtered.snapshot() == []

        t.emit(TrajectoryEntry(
            entry_type=MODEL_REQUEST, content="new", security_domain=_CHILD,
        ))
        assert len(t.filtered.snapshot()) == 1
        assert t.filtered.drain()[0].content == "new"

    def test_filtered_property_raises_without_scope(self) -> None:
        """Accessing .filtered without filtered_scope raises RuntimeError."""
        t = Trajectory()
        with pytest.raises(RuntimeError, match="No filtered view"):
            t.filtered

    def test_concurrent_emit_and_filtered_reads(self) -> None:
        """Thread safety: concurrent emit() and filtered snapshot()/drain()."""
        t = Trajectory(filtered_scope=_CHILD)
        n_emitters = 5
        n_per_emitter = 100
        barrier = threading.Barrier(n_emitters + 1)

        def emitter() -> None:
            barrier.wait()
            for i in range(n_per_emitter):
                t.emit(TrajectoryEntry(
                    entry_type=MODEL_REQUEST, content=str(i),
                    security_domain=_CHILD,
                ))

        def reader() -> None:
            barrier.wait()
            for _ in range(50):
                t.filtered.snapshot()

        threads = [threading.Thread(target=emitter) for _ in range(n_emitters)]
        threads.append(threading.Thread(target=reader))
        for th in threads:
            th.start()
        for th in threads:
            th.join()

        # All entries pushed through
        assert len(t.filtered.snapshot()) == n_emitters * n_per_emitter
