"""Concrete event and response types.

All concrete :class:`~superred.core.types.event.Event` and
:class:`~superred.core.types.event.EventResponse` subclasses live here.

Observable and controllable events auto-derive their ``security_domain``
from the referenced observable/controllable via ``__post_init__``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from superred.core.types.controllable import Controllable
from superred.core.types.evaluation import EvaluationResult
from superred.core.types.event import Event, EventResponse
from superred.core.types.observable import Observable
from superred.core.types.trajectory import ReadableTrajectory

# -- Observable events (one-way target logging) ------------------------------


@dataclass(frozen=True, kw_only=True)
class ObservableEvent(Event):
    """One-way observation emitted by the target during a run.

    Not routed through the channel — recorded directly on the trajectory.
    References an :class:`Observable` that defines the name and security
    domain. ``security_domain`` is auto-derived from the observable if
    not set.

    Attributes:
        observable: The observable this event reports on.
        content: The payload (string, dict, any serializable data).
    """

    observable: Observable
    content: Any

    def __post_init__(self) -> None:
        if self.security_domain is None:
            object.__setattr__(self, "security_domain", self.observable.security_domain)


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


# -- Run lifecycle events ----------------------------------------------------


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

    Sent by the controller after evaluation.  Persisted to the trajectory
    so the optimizer can read feedback from past runs.
    Valid responses: :class:`RunEndResponse`.

    When ``include_feedback=True`` (the default), ``evaluation`` carries
    the scope-filtered evaluation result.  When ``False``, ``evaluation``
    is ``None`` — the event is still persisted (the optimizer needs it
    for lifecycle) but carries no feedback data.

    The caller must set ``security_domain`` so the event passes trajectory
    validation.

    Attributes:
        evaluation: The (scope-filtered) evaluation result for this run,
            or ``None`` when feedback is disabled.
    """

    evaluation: EvaluationResult | None = None


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
