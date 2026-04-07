"""Middleware: composable transformations on the event handler callback.

A middleware wraps an ``EventHandler`` and returns a new one. This allows
modular insertion of filtering, recording, logging, tracing, etc. into
the event pipeline without modifying the controller or target.

Middleware is applied as function composition — zero overhead, no extra
tasks or channels::

    from superred.core.middleware import compose, security_domain_filter

    handler = compose(
        trajectory_recorder(trajectory),
        security_domain_filter(tag),
    )(channel.send)

Each middleware is ``Callable[[EventHandler], EventHandler]``.
``compose`` applies them left-to-right (outermost first).
"""

from __future__ import annotations

from collections.abc import Callable

from superred.core.types.event import Event, EventResponse, EventResponseHandler
from superred.core.types.events import (
    ControllableNoInjection,
    ControllablePostCallEvent,
    ControllablePreCallEvent,
)
from superred.core.types.security_domain import SecurityDomainTag
from superred.core.types.trajectory import Trajectory

# A middleware wraps an EventResponseHandler and returns a new one.
Middleware = Callable[[EventResponseHandler], EventResponseHandler]


def compose(*middlewares: Middleware) -> Middleware:
    """Compose middleware left-to-right (first listed = outermost).

    ``compose(a, b)(handler)`` means ``a(b(handler))``:
    events pass through *a* first, then *b*, then the inner handler.

    With no arguments, returns an identity middleware.
    """

    def apply(handler: EventResponseHandler) -> EventResponseHandler:
        result = handler
        for mw in reversed(middlewares):
            result = mw(result)
        return result

    return apply


def trajectory_recorder(trajectory: Trajectory) -> Middleware:
    """Middleware that records controllable events and responses on the trajectory.

    Each event is recorded directly before being forwarded.
    Each response is recorded directly after the inner handler returns.

    Security domains are derived automatically:
    - Events: from ``event.security_domain`` (auto-derived from controllable).
    - Responses: from ``response.event.security_domain`` via :func:`get_domain`.

    Args:
        trajectory: The trajectory to record items on.
    """

    def apply(handler: EventResponseHandler) -> EventResponseHandler:
        async def recording(event: Event) -> EventResponse:
            trajectory.emit(event)
            response = await handler(event)
            trajectory.emit(response)
            return response

        return recording

    return apply


def security_domain_filter(scope: SecurityDomainTag) -> Middleware:
    """Middleware that filters controllable events by security domain.

    Events for controllables outside *scope* are answered with
    :class:`ControllableNoInjection` without reaching the inner handler.

    Args:
        scope: The security domain tag to test against. Events whose
            controllable's domain is included by this tag pass through.
    """

    def apply(handler: EventResponseHandler) -> EventResponseHandler:
        async def filtered(event: Event) -> EventResponse:
            if isinstance(event, (ControllablePreCallEvent, ControllablePostCallEvent)):
                controllable_domain = event.controllable.security_domain
                if not scope.includes(controllable_domain):
                    return ControllableNoInjection(
                        event=event, controllable=event.controllable,
                    )

            return await handler(event)

        return filtered

    return apply
