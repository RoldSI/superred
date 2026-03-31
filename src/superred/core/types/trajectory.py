"""Trajectory: the ordered sequence of entries from a single run.

A run produces a trajectory T = <e1, ..., en> where each entry captures an
atomic operation in the target system.

Each entry's content is determined by its :class:`TrajectoryEntryType`.

All public methods are thread-safe: :meth:`emit`, :meth:`drain`,
:meth:`snapshot`, and :meth:`close` may be called concurrently from
multiple threads.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from superred.core.types.feedback import FeedbackResult


@dataclass(frozen=True)
class TrajectoryEntryType:
    """A runtime-registered type of trajectory entry.

    Each entry type declares the Python type of content that entries of
    this type carry.  Entry types are defined by target systems and
    registered on a :class:`Trajectory` instance.  Only
    :data:`MODEL_REQUEST` and :data:`MODEL_RESPONSE` are available by
    default.

    Attributes:
        name: Unique human-readable identifier.
        description: Human-readable description.
        content_type: The Python type that :attr:`TrajectoryEntry.content`
            must be for entries of this type.
    """

    name: str
    description: str
    actor: str
    content_type: type[Any]


# Default entry types — always available on every trajectory.
MODEL_REQUEST = TrajectoryEntryType(
    name="model_request",
    description="Prompt sent to the LLM model by the AI system",
    actor="AI system",
    content_type=str,
)
MODEL_RESPONSE = TrajectoryEntryType(
    name="model_response",
    description="Response received from the LLM model",
    actor="LLM model",
    content_type=str,
)
FEEDBACK = TrajectoryEntryType(
    name="feedback",
    description="Evaluation feedback for a run",
    actor="task evaluator",
    content_type=FeedbackResult,
)

DEFAULT_ENTRY_TYPES: frozenset[TrajectoryEntryType] = frozenset(
    {MODEL_REQUEST, MODEL_RESPONSE, FEEDBACK}
)


@dataclass
class TrajectoryEntry:
    """A single entry in a trajectory.

    The shape of :attr:`content` is determined by :attr:`entry_type` —
    see :attr:`TrajectoryEntryType.content_type`.

    Attributes:
        entry_type: The type of this entry.
        content: Payload whose type matches ``entry_type.content_type``.
        timestamp: When the entry was created.
    """

    entry_type: TrajectoryEntryType
    content: Any
    timestamp: datetime = field(default_factory=datetime.now)


class Trajectory:
    """A thread-safe stream of trajectory entries for one run.

    The target system calls :meth:`emit` to push entries and :meth:`close`
    to signal completion. Consumers read via :meth:`drain` (new entries
    since last drain) or :meth:`snapshot` (full trajectory so far).

    Entry types are registered at construction. The defaults
    (:data:`MODEL_REQUEST`, :data:`MODEL_RESPONSE`) are always available;
    targets add their own via *entry_types*.

    All public methods are safe to call concurrently from multiple threads.
    """

    def __init__(
        self,
        entry_types: Sequence[TrajectoryEntryType] = (),
    ) -> None:
        self._lock = threading.Lock()
        self._entry_types: frozenset[TrajectoryEntryType] = DEFAULT_ENTRY_TYPES | frozenset(
            entry_types
        )
        self._entries: list[TrajectoryEntry] = []
        self._closed: bool = False
        self._drain_cursor: int = 0

    def emit(self, entry: TrajectoryEntry) -> None:
        """Push an entry into the stream (producer side).

        Raises:
            RuntimeError: If the trajectory has already been closed.
        """
        with self._lock:
            if self._closed:
                raise RuntimeError("Cannot emit to a closed trajectory")
            self._entries.append(entry)

    def close(self) -> None:
        """Signal that no more entries will be emitted."""
        with self._lock:
            self._closed = True

    def snapshot(self) -> list[TrajectoryEntry]:
        """Return all entries emitted so far without advancing the drain cursor."""
        with self._lock:
            return list(self._entries)

    def drain(self) -> list[TrajectoryEntry]:
        """Return all entries emitted since the last ``drain()`` call.

        Non-blocking: returns immediately with whatever is available.
        If no new entries exist, returns an empty list.
        """
        with self._lock:
            new_entries = self._entries[self._drain_cursor :]
            self._drain_cursor = len(self._entries)
            return new_entries
