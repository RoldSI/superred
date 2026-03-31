"""Execution context types for security claim evaluation.

These types provide the normalized representations of actions, observations,
and execution context that security claims operate over.  They are
target-agnostic by design, enabling transferable claims across different
target systems.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Optional, Sequence

from superred.core.types.trajectory import TraceEvent


@dataclass(frozen=True)
class ActionRecord:
    """A normalized record of a single action taken by the agent."""

    action_id: str
    action_type: str
    name: str
    arguments: Mapping[str, Any]
    destination_sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class ObservationRecord:
    """A normalized record of a single observation received by the agent."""

    observation_id: str
    source_ids: tuple[str, ...]
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class TurnResult:
    """Result of a single step in a target run."""

    action: Optional[ActionRecord]
    observation: Optional[ObservationRecord]
    new_events: Sequence[TraceEvent]
    done: bool
    info: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ContextSnapshot:
    """A normalized snapshot of the execution context at a point in time.

    Security claims evaluate predicates over this context plus oracle
    functions, rather than over concrete target objects.  This is what
    makes claims transferable across heterogeneous target systems.
    """

    user_prompt: str
    trajectory: Sequence[tuple[ActionRecord, ObservationRecord]]
    memory: Sequence[Mapping[str, Any]]
    environment_state: Mapping[str, Any]
    authenticated_sources: frozenset[str]
    permission_edges: frozenset[tuple[str, str]]
