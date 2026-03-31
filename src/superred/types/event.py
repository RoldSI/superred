"""Event types for communication between targets and optimizers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import uuid4

from superred.types.controllable import ControllableSpec
from superred.types.security import SecurityDomainTag


@dataclass(frozen=True, kw_only=True)
class Event:
    """Base event emitted by a target at a controllable point."""
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    security_domain: SecurityDomainTag | None = None


@dataclass(frozen=True, kw_only=True)
class EventResponse:
    """Base response from an optimizer to an event."""
    event: Event


@dataclass(frozen=True, kw_only=True)
class ControllablePreCallEvent(Event):
    """Target is about to execute at a controllable point."""
    controllable: ControllableSpec
    request: str


@dataclass(frozen=True, kw_only=True)
class ControllablePostCallEvent(Event):
    """Target completed a controllable point. Informational."""
    controllable: ControllableSpec
    request: str
    answer: str


@dataclass(frozen=True, kw_only=True)
class ControllableInjection(EventResponse):
    """Optimizer injects modified content at a controllable point."""
    value: str


@dataclass(frozen=True, kw_only=True)
class PassThrough(EventResponse):
    """Optimizer declines to inject. Target proceeds normally."""


@dataclass(frozen=True, kw_only=True)
class OptimizerDoneEvent(Event):
    """Optimizer signals it has exhausted its strategy space."""
