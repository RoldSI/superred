"""Trajectory: the ordered sequence of entries from a single run.

A run produces a trajectory T = <e1, ..., en> where each entry captures an
atomic operation in the target system.

Each entry's content is determined by its :class:`TrajectoryEntryType`.
Each entry is tagged with a :class:`SecurityDomainTag` indicating which
security scope it belongs to.

All public methods are thread-safe: :meth:`emit`, :meth:`drain`,
:meth:`snapshot`, and :meth:`close` may be called concurrently from
multiple threads.

:class:`FilteredTrajectory` provides a read-only view filtered by a
security domain scope.
"""

from __future__ import annotations

import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from superred.core.types.evaluation import FeedbackResult
from superred.core.types.security_domain import SecurityDomainTag


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
        security_domain: The security domain scope this entry belongs to.
        timestamp: When the entry was created.
    """

    entry_type: TrajectoryEntryType
    content: Any
    security_domain: SecurityDomainTag
    timestamp: datetime = field(default_factory=datetime.now)


class Trajectory:
    """A thread-safe stream of trajectory entries for one run.

    The target system calls :meth:`emit` to push entries and :meth:`close`
    to signal completion. Consumers read via :meth:`drain` (new entries
    since last drain) or :meth:`snapshot` (full trajectory so far).

    Pass *filtered_scope* to create a :class:`FilteredTrajectory` that
    receives in-scope entries at emit time, accessible via :attr:`filtered`.
    The filtered view holds no reference back to this trajectory.

    Entry types are registered at construction. The defaults
    (:data:`MODEL_REQUEST`, :data:`MODEL_RESPONSE`) are always available;
    targets add their own via *entry_types*.

    All public methods are safe to call concurrently from multiple threads.
    """

    def __init__(
        self,
        entry_types: Sequence[TrajectoryEntryType] = (),
        filtered_scope: SecurityDomainTag | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._entry_types: frozenset[TrajectoryEntryType] = DEFAULT_ENTRY_TYPES | frozenset(
            entry_types
        )
        self._entries: list[TrajectoryEntry] = []
        self._closed: bool = False
        self._drain_cursor: int = 0
        # Optional filtered view — set once at construction, immutable.
        self._filter: tuple[SecurityDomainTag, FilteredTrajectory] | None = None
        if filtered_scope is not None:
            self._filter = (filtered_scope, FilteredTrajectory())

    def emit(self, entry: TrajectoryEntry) -> None:
        """Push an entry into the stream (producer side).

        If a filtered view exists, matching entries are pushed to it.

        Raises:
            RuntimeError: If the trajectory has already been closed.
        """
        with self._lock:
            if self._closed:
                raise RuntimeError("Cannot emit to a closed trajectory")
            self._entries.append(entry)
            if self._filter is not None:
                scope, view = self._filter
                if scope.includes(entry.security_domain):
                    view._push(entry)

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

    @property
    def filtered(self) -> FilteredTrajectory:
        """The filtered view, if *filtered_scope* was provided at construction.

        Raises:
            RuntimeError: If no filtered scope was configured.
        """
        if self._filter is None:
            raise RuntimeError(
                "No filtered view — pass filtered_scope to Trajectory constructor"
            )
        return self._filter[1]


class FilteredTrajectory:
    """Read-only view of trajectory entries within a security domain scope.

    Created by passing *filtered_scope* to the :class:`Trajectory`
    constructor, then accessed via :attr:`Trajectory.filtered`.  Entries
    are pushed by the parent trajectory at emit time.

    **Encapsulation**: This object holds **no reference** to the
    underlying :class:`Trajectory`.  Entries flow one direction only
    (push at emit time), so the consumer cannot reach unfiltered data
    through any attribute, closure, or other mechanism.
    ``__slots__`` prevents ``__dict__``, blocking arbitrary attribute
    injection.

    :meth:`snapshot` and :meth:`drain` are thread-safe.
    """

    __slots__ = ("_entries", "_lock", "_drain_cursor")

    def __init__(self) -> None:
        self._entries: list[TrajectoryEntry] = []
        self._lock = threading.Lock()
        self._drain_cursor: int = 0

    def _push(self, entry: TrajectoryEntry) -> None:
        """Receive a pre-filtered entry from the parent trajectory.

        Called by :class:`Trajectory` during :meth:`~Trajectory.emit`.
        Not part of the public API.
        """
        with self._lock:
            self._entries.append(entry)

    def snapshot(self) -> list[TrajectoryEntry]:
        """Return all in-scope entries received so far."""
        with self._lock:
            return list(self._entries)

    def drain(self) -> list[TrajectoryEntry]:
        """Return in-scope entries received since the last ``drain()`` call.

        Maintains its own cursor independent of the parent trajectory.
        """
        with self._lock:
            new_entries = self._entries[self._drain_cursor :]
            self._drain_cursor = len(self._entries)
            return list(new_entries)


ReadableTrajectory = Trajectory | FilteredTrajectory
"""Type alias for objects that expose ``snapshot()`` and ``drain()``."""
