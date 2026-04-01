"""Event types dispatched to the optimizer during target runs.

Events represent discrete interaction points between the target system
and the optimizer.  Each concrete event type has a corresponding response
type that the optimizer must return.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from superred.core.types.controllable import Controllable


@dataclass(frozen=True, kw_only=True)
class Event:
    """Base class for all events dispatched to the optimizer.

    Attributes:
        event_id: Unique identifier for this event instance.
        timestamp: When the event was created.
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass(frozen=True, kw_only=True)
class EventResponse:
    """Base class for optimizer responses to events.

    Attributes:
        event: The event this response was produced for.
    """

    event: Event


# -- Controllable events -----------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class ControllablePreCallEvent(Event):
    """A controllable injection point has been reached.

    The optimizer must respond with a :class:`ControllableInjection`.

    Attributes:
        controllable: The injection point that was reached.
        request: The current request to the controllable.
    """

    controllable: Controllable
    request: str


@dataclass(frozen=True, kw_only=True)
class ControllablePostCallEvent(Event):
    """A controllable's injected value has been used by the target.

    Sent after injection so the optimizer can observe the effect.

    Attributes:
        controllable: The injection point that was used.
        request: The request that was made.
        answer: The answer that was produced.
    """

    controllable: Controllable
    request: str
    answer: str


@dataclass(frozen=True, kw_only=True)
class ControllableInjection(EventResponse):
    """The optimizer's injection for a controllable.

    Returned as the response to a :class:`ControllablePreCallEvent` or
    :class:`ControllablePostCallEvent`.

    Attributes:
        value: The string value to inject.
    """

    value: str


@dataclass(frozen=True, kw_only=True)
class NoModification(EventResponse):
    """No modification — controllable is outside the active security domain scope.

    Returned by the controller when an event's controllable falls outside
    the security domain tag being tested, so the optimizer is not consulted.
    """


# -- Optimizer lifecycle events ----------------------------------------------


@dataclass(frozen=True, kw_only=True)
class OptimizerDoneEvent(Event):
    """The optimizer signals that it has finished optimizing.

    Returned from :meth:`Optimizer.on_post_run` to indicate the optimizer
    considers itself done (e.g. goal achieved, budget exhausted).
    The framework should stop scheduling further runs.
    """
