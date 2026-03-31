"""Canonical event-based trajectory for representing a single run.

A run produces a trajectory T = <e1, ..., en> where each event captures an
atomic operation in the target system.  This schema is grounded in
OpenTelemetry GenAI conventions and OpenInference semantics, with W3C
PROV-style provenance.

Large payloads are stored in a typed artifact store referenced by events,
keeping the trace lightweight while supporting text, JSON, images, and files.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Optional


class EventKind(str, Enum):
    """Canonical vocabulary of operation types in a trajectory."""

    USER_INPUT = "user_input"
    SYSTEM_CONTEXT = "system_context"
    MODEL_REQUEST = "model_request"
    MODEL_RESPONSE = "model_response"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    RETRIEVAL_QUERY = "retrieval_query"
    RETRIEVAL_RESULT = "retrieval_result"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    VERIFIER_INPUT = "verifier_input"
    VERIFIER_OUTPUT = "verifier_output"
    INJECTION = "injection"
    ERROR = "error"


@dataclass(frozen=True)
class TraceEvent:
    """A single event in a canonical trajectory.

    Each event contains: identity, ordering, actor, operation, security tags,
    payload, and cost — enough to support replay, filtering, attribution, and
    budgeting.
    """

    event_id: str
    parent_event_id: Optional[str]
    timestamp_ms: int
    actor: str
    kind: EventKind
    domains: frozenset[str]
    payload: Mapping[str, Any]
    cost: Mapping[str, float | int] = field(default_factory=dict)


@dataclass(frozen=True)
class Artifact:
    """A typed payload referenced by trace events.

    Keeps large data out of the trace itself while maintaining typed
    references.
    """

    artifact_id: str
    mime_type: str = "text/plain"
    data: Any = None
    label: str = ""
