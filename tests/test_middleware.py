"""Unit tests for middleware: compose() and security_domain_filter()."""

from __future__ import annotations

import threading

from superred.core.middleware import (
    EventHandler,
    Middleware,
    compose,
    security_domain_filter,
)
from superred.core.types.controllable import Controllable, ControllableSpec
from superred.core.types.event import (
    ControllableInjection,
    ControllablePostCallEvent,
    ControllablePreCallEvent,
    Event,
    EventResponse,
    NoModification,
    RunStartEvent,
)
from superred.core.types.security_domain import SecurityDomainTag
from superred.core.types.trajectory import Trajectory

PARENT_TAG = SecurityDomainTag("parent")
CHILD_TAG = SecurityDomainTag("child", parent=PARENT_TAG)
SIBLING_TAG = SecurityDomainTag("sibling", parent=PARENT_TAG)


# ---------------------------------------------------------------------------
# compose()
# ---------------------------------------------------------------------------


class TestCompose:
    async def test_identity(self) -> None:
        """compose() with no middlewares returns the handler unchanged."""
        calls: list[Event] = []

        async def handler(event: Event) -> EventResponse:
            calls.append(event)
            return EventResponse(event=event)

        wrapped = compose()(handler)
        event = RunStartEvent(trajectory=Trajectory())
        await wrapped(event)
        assert len(calls) == 1

    async def test_ordering_left_to_right(self) -> None:
        """Middlewares apply left-to-right (first listed = outermost)."""
        order: list[str] = []

        def make_mw(name: str) -> Middleware:
            def mw(handler: EventHandler) -> EventHandler:
                async def wrapped(event: Event) -> EventResponse:
                    order.append(f"{name}_before")
                    resp = await handler(event)
                    order.append(f"{name}_after")
                    return resp
                return wrapped
            return mw

        async def inner(event: Event) -> EventResponse:
            order.append("inner")
            return EventResponse(event=event)

        wrapped = compose(make_mw("a"), make_mw("b"))(inner)
        await wrapped(RunStartEvent(trajectory=Trajectory()))

        assert order == ["a_before", "b_before", "inner", "b_after", "a_after"]

    async def test_single_middleware(self) -> None:
        """compose(a)(handler) == a(handler)."""
        called = False

        def mw(handler: EventHandler) -> EventHandler:
            async def wrapped(event: Event) -> EventResponse:
                nonlocal called
                called = True
                return await handler(event)
            return wrapped

        async def handler(event: Event) -> EventResponse:
            return EventResponse(event=event)

        wrapped = compose(mw)(handler)
        await wrapped(Event())
        assert called


# ---------------------------------------------------------------------------
# security_domain_filter()
# ---------------------------------------------------------------------------


class TestSecurityDomainFilter:
    async def test_blocks_out_of_scope_pre_call(self) -> None:
        """Pre-call event for a domain outside scope is blocked."""
        async def handler(event: Event) -> EventResponse:
            return ControllableInjection(event=event, value="x")

        filtered = security_domain_filter(CHILD_TAG)(handler)

        # SIBLING_TAG is NOT included by CHILD_TAG
        c = Controllable(spec=ControllableSpec(name="c", security_domain=SIBLING_TAG))
        event = ControllablePreCallEvent(controllable=c, request="hi")
        response = await filtered(event)

        assert isinstance(response, NoModification)

    async def test_blocks_out_of_scope_post_call(self) -> None:
        """Post-call event outside scope is also blocked."""
        async def handler(event: Event) -> EventResponse:
            return EventResponse(event=event)

        filtered = security_domain_filter(CHILD_TAG)(handler)

        c = Controllable(spec=ControllableSpec(name="c", security_domain=SIBLING_TAG))
        event = ControllablePostCallEvent(controllable=c, request="hi", answer="bye")
        response = await filtered(event)

        assert isinstance(response, NoModification)

    async def test_passes_in_scope(self) -> None:
        """Events within scope are forwarded to the handler."""
        async def handler(event: Event) -> EventResponse:
            return ControllableInjection(event=event, value="x")

        filtered = security_domain_filter(PARENT_TAG)(handler)

        c = Controllable(spec=ControllableSpec(name="c", security_domain=CHILD_TAG))
        event = ControllablePreCallEvent(controllable=c, request="hi")
        response = await filtered(event)

        assert isinstance(response, ControllableInjection)

    async def test_passes_non_controllable_events(self) -> None:
        """Non-controllable events always pass through."""
        async def handler(event: Event) -> EventResponse:
            return EventResponse(event=event)

        filtered = security_domain_filter(CHILD_TAG)(handler)
        event = RunStartEvent(trajectory=Trajectory())
        response = await filtered(event)

        assert isinstance(response, EventResponse)

    async def test_event_log_with_lock(self) -> None:
        """Event log is populated when provided with a lock."""
        log: list[tuple[Event, EventResponse]] = []
        lock = threading.Lock()

        async def handler(event: Event) -> EventResponse:
            return ControllableInjection(event=event, value="x")

        filtered = security_domain_filter(PARENT_TAG, event_log=log, event_log_lock=lock)(handler)

        c = Controllable(spec=ControllableSpec(name="c", security_domain=CHILD_TAG))
        event = ControllablePreCallEvent(controllable=c, request="hi")
        await filtered(event)

        assert len(log) == 1
        assert log[0][0] is event

    async def test_event_log_without_lock(self) -> None:
        """Event log works without a lock (single-threaded usage)."""
        log: list[tuple[Event, EventResponse]] = []

        async def handler(event: Event) -> EventResponse:
            return ControllableInjection(event=event, value="x")

        filtered = security_domain_filter(PARENT_TAG, event_log=log)(handler)

        c = Controllable(spec=ControllableSpec(name="c", security_domain=CHILD_TAG))
        event = ControllablePreCallEvent(controllable=c, request="hi")
        await filtered(event)

        assert len(log) == 1

    async def test_no_log_when_not_provided(self) -> None:
        """No logging when event_log is None (default). Handler still runs."""
        async def handler(event: Event) -> EventResponse:
            return EventResponse(event=event)

        filtered = security_domain_filter(PARENT_TAG)(handler)
        response = await filtered(RunStartEvent(trajectory=Trajectory()))
        assert isinstance(response, EventResponse)

    async def test_blocked_event_logged(self) -> None:
        """Blocked events are still logged with NoModification response."""
        log: list[tuple[Event, EventResponse]] = []

        async def handler(event: Event) -> EventResponse:
            raise AssertionError("Should not be called")

        filtered = security_domain_filter(CHILD_TAG, event_log=log)(handler)

        c = Controllable(spec=ControllableSpec(name="c", security_domain=SIBLING_TAG))
        event = ControllablePreCallEvent(controllable=c, request="hi")
        await filtered(event)

        assert len(log) == 1
        assert isinstance(log[0][1], NoModification)
