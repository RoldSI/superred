"""Canonical event-based trajectory for representing a single run.

A run produces a trajectory T = <e1, ..., en> where each event captures an
atomic operation in the target system. This schema is grounded in OpenTelemetry
GenAI conventions and OpenInference semantics, with W3C PROV-style provenance.

Large payloads are stored in a typed artifact store referenced by events,
keeping the trace lightweight while supporting text, JSON, images, and files.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from superred.core.types.threat_model import SecurityTag


class OperationType(enum.Enum):
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
    VERIFIER_RESULT = "verifier_result"
    INJECTION = "injection"
    ERROR = "error"
    CUSTOM = "custom"


@dataclass(frozen=True)
class CostRecord:
    """Token and monetary cost for a single operation.

    Attributes:
        input_tokens: Number of input tokens consumed.
        output_tokens: Number of output tokens produced.
        total_tokens: Total tokens (may differ from sum if caching applies).
        cost_usd: Monetary cost in USD, if known.
        model: Model identifier, if applicable.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float | None = None
    model: str | None = None


@dataclass(frozen=True)
class Artifact:
    """A typed payload referenced by trace events.

    Keeps large data out of the trace itself while maintaining typed references.

    Attributes:
        artifact_id: Unique identifier.
        mime_type: MIME type (e.g. "text/plain", "application/json", "image/png").
        data: The actual payload. Type depends on mime_type.
        label: Optional human-readable label.
    """

    artifact_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    mime_type: str = "text/plain"
    data: Any = None
    label: str = ""


@dataclass
class TraceEvent:
    """A single event in a canonical trajectory.

    Attributes:
        event_id: Unique identifier for this event.
        parent_id: ID of the parent event (for nesting/causality), or None.
        timestamp: When the event occurred.
        actor: Identifier of the component that produced this event.
        operation: The type of operation.
        security_tags: Security domain tags for this event.
        inputs: Typed input data or artifact references.
        outputs: Typed output data or artifact references.
        cost: Token/monetary cost, if applicable.
        metadata: Arbitrary additional metadata.
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    parent_id: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)
    actor: str = ""
    operation: OperationType = OperationType.CUSTOM
    security_tags: frozenset[SecurityTag] = field(default_factory=frozenset)
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    cost: CostRecord | None = None
    artifacts: list[Artifact] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Trajectory:
    """A complete trajectory for one run of the target system.

    Attributes:
        run_id: Unique identifier for this run.
        events: Ordered list of trace events.
        total_cost: Aggregated cost across all events.
        metadata: Run-level metadata (e.g. threat model name, timestamps).
    """

    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    events: list[TraceEvent] = field(default_factory=list)
    total_cost: CostRecord = field(default_factory=CostRecord)
    metadata: dict[str, Any] = field(default_factory=dict)

    def append(self, event: TraceEvent) -> None:
        """Append an event to the trajectory."""
        self.events.append(event)

    def filter_by_tags(self, tags: frozenset[SecurityTag]) -> Trajectory:
        """Return a new trajectory containing only events matching any of the given tags.

        This implements the projection operator O(M, T) — filtering the full
        trajectory by the security tags exposed in a threat model.
        """
        filtered = [e for e in self.events if e.security_tags & tags]
        return Trajectory(
            run_id=self.run_id,
            events=filtered,
            total_cost=self.total_cost,
            metadata=self.metadata,
        )

    def filter_by_operations(self, ops: set[OperationType]) -> Trajectory:
        """Return a new trajectory containing only events of the given operation types."""
        filtered = [e for e in self.events if e.operation in ops]
        return Trajectory(
            run_id=self.run_id,
            events=filtered,
            total_cost=self.total_cost,
            metadata=self.metadata,
        )
