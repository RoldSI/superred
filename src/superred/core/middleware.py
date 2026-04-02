"""Middleware: composable transformations on the event handler callback.

A middleware wraps an ``EventHandler`` and returns a new one. This allows
modular insertion of filtering, logging, tracing, etc. into the event
pipeline without modifying the controller or target.

Middleware is applied as function composition — zero overhead, no extra
tasks or channels::

    from superred.core.middleware import compose, security_domain_filter

    handler = compose(
        security_domain_filter(tag, event_log),
        my_custom_logger,
    )(channel.send)

Each middleware is ``Callable[[EventHandler], EventHandler]``.
``compose`` applies them left-to-right (outermost first).
"""

from __future__ import annotations

import threading
from collections.abc import Awaitable, Callable

from superred.core.types.event import (
    ControllablePostCallEvent,
    ControllablePreCallEvent,
    Event,
    EventResponse,
    NoModification,
)
from superred.core.types.security_domain import SecurityDomainTag

# The callback type (same as in target.py, re-declared to avoid circular import)
EventHandler = Callable[[Event], Awaitable[EventResponse]]

# A middleware wraps an EventHandler and returns a new one.
Middleware = Callable[[EventHandler], EventHandler]


def compose(*middlewares: Middleware) -> Middleware:
    """Compose middleware left-to-right (first listed = outermost).

    ``compose(a, b)(handler)`` means ``a(b(handler))``:
    events pass through *a* first, then *b*, then the inner handler.

    With no arguments, returns an identity middleware.
    """

    def apply(handler: EventHandler) -> EventHandler:
        result = handler
        for mw in reversed(middlewares):
            result = mw(result)
        return result

    return apply


def security_domain_filter(
    scope: SecurityDomainTag,
    event_log: list[tuple[Event, EventResponse]] | None = None,
    event_log_lock: threading.Lock | None = None,
) -> Middleware:
    """Middleware that filters controllable events by security domain.

    Events for controllables outside *scope* are answered with
    :class:`NoModification` without reaching the inner handler.

    Args:
        scope: The security domain tag to test against. Events whose
            controllable's domain is included by this tag pass through.
        event_log: Optional list to append ``(event, response)`` pairs to.
        event_log_lock: Lock protecting *event_log* for thread safety.
    """

    def apply(handler: EventHandler) -> EventHandler:
        async def filtered(event: Event) -> EventResponse:
            if isinstance(event, (ControllablePreCallEvent, ControllablePostCallEvent)):
                controllable_domain = event.controllable.spec.security_domain
                if not scope.includes(controllable_domain):
                    response: EventResponse = NoModification(event=event)
                    _log(event, response, event_log, event_log_lock)
                    return response

            response = await handler(event)
            _log(event, response, event_log, event_log_lock)
            return response

        return filtered

    return apply


def _log(
    event: Event,
    response: EventResponse,
    event_log: list[tuple[Event, EventResponse]] | None,
    lock: threading.Lock | None,
) -> None:
    """Append to event log if provided. Thread-safe."""
    if event_log is None:
        return
    if lock is not None:
        with lock:
            event_log.append((event, response))
    else:
        event_log.append((event, response))
