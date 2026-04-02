"""Event types dispatched to the optimizer during target runs.

Events represent discrete interaction points between the target system
and the optimizer.  Each concrete event type declares valid response types
via the ``response_types`` class variable, validated at runtime by
:meth:`EventEnvelope.respond`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import ClassVar

from superred.core.types.controllable import Controllable
from superred.core.types.trajectory import ReadableTrajectory


@dataclass(frozen=True, kw_only=True)
class Event:
    """Base class for all events dispatched to the optimizer.

    Subclasses declare ``response_types`` as a :class:`ClassVar` tuple of
    allowed response classes.  Empty tuple means any :class:`EventResponse`
    is accepted (the default for base Event).

    Attributes:
        event_id: Unique identifier for this event instance.
        timestamp: When the event was created.
    """

    response_types: ClassVar[tuple[type[EventResponse], ...]] = ()

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

    Valid responses: :class:`ControllableInjection`, :class:`NoModification`.

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
    Valid responses: :class:`ControllableInjection`, :class:`NoModification`.

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
    Also used as a fallback response when the optimizer encounters an error.
    """


# -- Run lifecycle events ----------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class RunStartEvent(Event):
    """Signals the start of a new target run.

    Sent by the controller before ``target.run()`` begins.
    Valid responses: any :class:`EventResponse`.

    Attributes:
        trajectory: The trajectory for the new run (may be a
            :class:`FilteredTrajectory` when sent to the optimizer).
    """

    trajectory: ReadableTrajectory


@dataclass(frozen=True, kw_only=True)
class RunEndEvent(Event):
    """Signals the end of a target run.

    Sent by the controller after ``target.run()`` completes.
    Valid responses: :class:`RunEndResponse`.

    Attributes:
        trajectory: The trajectory for the completed run (may be a
            :class:`FilteredTrajectory` when sent to the optimizer).
    """

    trajectory: ReadableTrajectory


@dataclass(frozen=True, kw_only=True)
class RunEndResponse(EventResponse):
    """Response to a :class:`RunEndEvent`.

    Set ``done=True`` to signal the optimizer wants to stop
    (e.g. goal achieved, budget exhausted).

    Attributes:
        done: Whether the optimizer considers itself finished.
    """

    done: bool = False


# ---------------------------------------------------------------------------
# Wire up response_types after all classes are defined.
# ClassVar fields are not part of __init__ or __eq__, so setting them
# after class creation is safe for frozen dataclasses.
# ---------------------------------------------------------------------------

ControllablePreCallEvent.response_types = (ControllableInjection, NoModification)
ControllablePostCallEvent.response_types = (ControllableInjection, NoModification)
RunStartEvent.response_types = (EventResponse,)
RunEndEvent.response_types = (RunEndResponse,)
