"""Concrete event and response types.

All concrete :class:`~superred.core.types.event.Event` and
:class:`~superred.core.types.event.EventResponse` subclasses live here.

Controllable events auto-derive their ``security_domain`` from the
controllable's domain via ``__post_init__``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from superred.core.types.controllable import Controllable
from superred.core.types.evaluation import EvaluationResult
from superred.core.types.event import Event, EventResponse
from superred.core.types.trajectory import ReadableTrajectory

# -- One-way events (target logging) -----------------------------------------


@dataclass(frozen=True, kw_only=True)
class LogEvent(Event):
    """One-way logging event emitted by the target.

    Not routed through the channel — recorded directly on the trajectory.

    Attributes:
        content: The payload (string, dict, any serializable data).
        label: Optional human-readable label (e.g. ``"model_request"``).
    """

    content: Any
    label: str = ""


# -- Controllable events -----------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class ControllablePreCallEvent(Event):
    """A controllable injection point has been reached.

    Valid responses: :class:`ControllableInjection`,
    :class:`ControllableNoInjection`.

    ``security_domain`` is auto-derived from the controllable if not set.

    Attributes:
        controllable: The injection point that was reached.
        request: The current request to the controllable.
    """

    controllable: Controllable
    request: str

    def __post_init__(self) -> None:
        if self.security_domain is None:
            object.__setattr__(self, "security_domain", self.controllable.security_domain)


@dataclass(frozen=True, kw_only=True)
class ControllablePostCallEvent(Event):
    """A controllable's injected value has been used by the target.

    Sent after injection so the optimizer can observe the effect.
    Valid responses: :class:`ControllableInjection`,
    :class:`ControllableNoInjection`.

    ``security_domain`` is auto-derived from the controllable if not set.

    Attributes:
        controllable: The injection point that was used.
        request: The request that was made.
        answer: The answer that was produced.
    """

    controllable: Controllable
    request: str
    answer: str

    def __post_init__(self) -> None:
        if self.security_domain is None:
            object.__setattr__(self, "security_domain", self.controllable.security_domain)


@dataclass(frozen=True, kw_only=True)
class ControllableInjection(EventResponse):
    """The optimizer's injection for a controllable.

    Attributes:
        controllable: The injection point this response is for.
        value: The string value to inject.
    """

    controllable: Controllable
    value: str


@dataclass(frozen=True, kw_only=True)
class ControllableNoInjection(EventResponse):
    """No injection — controllable is outside the active security domain scope.

    Returned by the controller when an event's controllable falls outside
    the security domain tag being tested, so the optimizer is not consulted.

    Attributes:
        controllable: The injection point that was not modified.
    """

    controllable: Controllable


# -- Feedback event ----------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class FeedbackEvent(Event):
    """Evaluation feedback appended by the controller after each run.

    Attributes:
        evaluation: The (possibly filtered) evaluation result.
    """

    evaluation: EvaluationResult


# -- Run lifecycle events (channel only, NOT persisted to trajectory) --------


@dataclass(frozen=True, kw_only=True)
class RunStartEvent(Event):
    """Signals the start of a new target run.

    Sent by the controller before ``target.run()`` begins.
    NOT persisted to the trajectory.
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
    NOT persisted to the trajectory.
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
# ---------------------------------------------------------------------------

ControllablePreCallEvent.response_types = (ControllableInjection, ControllableNoInjection)
ControllablePostCallEvent.response_types = (ControllableInjection, ControllableNoInjection)
RunStartEvent.response_types = (EventResponse,)
RunEndEvent.response_types = (RunEndResponse,)
