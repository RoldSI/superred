"""Channel middleware: composable transformations on async channels."""

from __future__ import annotations

import asyncio
import logging
from typing import Callable, TypeVar

from superred.channels.channel import Channel, AsyncSender, channel
from superred.types.event import Event
from superred.types.security import ThreatModel
from superred.types.trajectory import Trajectory, TrajectoryEntry, TrajectoryEntryType
from superred.types.budget import HierarchicalBudget

logger = logging.getLogger(__name__)

T = TypeVar("T")

# A Middleware is a callable that wraps a Channel[T] and returns a new Channel[T].
Middleware = Callable[[Channel[T]], Channel[T]]

# Generic trace entry type used by trace_recorder for events that don't map
# to a more specific trajectory entry type.
TRACE = TrajectoryEntryType("trace", "middleware", Event)


def _pipe(
    inner: Channel[T],
    process: Callable[[T, AsyncSender[T]], bool] | None = None,
) -> Channel[T]:
    """Create a middleware pipe around an inner channel.

    Spawns a background task that reads from inner.receiver, optionally
    processes each item via ``process(item, outer_sender)``, and writes
    to the outer channel's sender.

    If ``process`` is None, items are forwarded unchanged (identity pipe).

    ``process`` returns True to continue, False to stop the pipe.

    Returns a Channel where:
      - sender = inner.sender  (target writes here)
      - receiver = outer.receiver  (optimizer reads here)
    """
    outer = channel[T]()

    async def _run() -> None:
        try:
            async for item in inner.receiver:
                if process is not None:
                    should_continue = process(item, outer.sender)
                    if not should_continue:
                        break
                else:
                    await outer.sender.send(item)
        except StopAsyncIteration:
            pass
        finally:
            outer.sender.close()

    asyncio.ensure_future(_run())
    return Channel(sender=inner.sender, receiver=outer.receiver)


def _async_pipe(
    inner: Channel[T],
    process: Callable[[T, AsyncSender[T]], object] | None = None,
) -> Channel[T]:
    """Like _pipe but process is an async callable returning bool."""
    outer = channel[T]()

    async def _run() -> None:
        try:
            async for item in inner.receiver:
                if process is not None:
                    should_continue = await process(item, outer.sender)  # type: ignore[misc]
                    if not should_continue:
                        break
                else:
                    await outer.sender.send(item)
        except StopAsyncIteration:
            pass
        finally:
            outer.sender.close()

    asyncio.ensure_future(_run())
    return Channel(sender=inner.sender, receiver=outer.receiver)


def compose(*middlewares: Middleware[T]) -> Middleware[T]:
    """Compose multiple middleware into one, applied left-to-right.

    ``compose(a, b)(ch)`` is equivalent to ``b(a(ch))``.
    With no arguments, returns an identity middleware.
    """

    def _apply(ch: Channel[T]) -> Channel[T]:
        if not middlewares:
            # Identity: still pipe through so we return a proper Channel pair.
            return _pipe(ch)
        result = ch
        for mw in middlewares:
            result = mw(result)
        return result

    return _apply


def trace_recorder(trajectory: Trajectory) -> Middleware[Event]:
    """Middleware that records every event to a Trajectory, then forwards it."""

    def _apply(ch: Channel[Event]) -> Channel[Event]:
        async def _process(item: Event, sender: AsyncSender[Event]) -> bool:
            entry = TrajectoryEntry(
                entry_type=TRACE,
                content=item,
                security_domain=getattr(item, "security_domain", None),
            )
            await trajectory.emit(entry)
            await sender.send(item)
            return True

        return _async_pipe(ch, _process)

    return _apply  # type: ignore[return-value]


def threat_model_filter(tm: ThreatModel) -> Middleware[Event]:
    """Middleware that drops events whose security_domain is outside the threat model's scope.

    The threat model's scope is determined by its ``controllables``,
    ``observables``, and ``feedback`` sets.  An event's
    ``security_domain.name`` is checked against the union of those sets.

    Events with ``security_domain=None`` always pass through (they are
    framework events like OptimizerDoneEvent).
    """
    allowed_names: frozenset[str] = tm.controllables | tm.observables | tm.feedback

    def _is_allowed(domain_name: str) -> bool:
        return domain_name in allowed_names

    def _apply(ch: Channel[Event]) -> Channel[Event]:
        async def _process(item: Event, sender: AsyncSender[Event]) -> bool:
            domain = getattr(item, "security_domain", None)
            if domain is None:
                # No domain tag -> framework event, always pass through.
                await sender.send(item)
            elif _is_allowed(domain.name):
                await sender.send(item)
            # else: drop silently
            return True

        return _async_pipe(ch, _process)

    return _apply  # type: ignore[return-value]


def budget_enforcer(hb: HierarchicalBudget) -> Middleware[Event]:
    """Middleware that records iterations and stops forwarding when budget is exhausted."""

    def _apply(ch: Channel[Event]) -> Channel[Event]:
        async def _process(item: Event, sender: AsyncSender[Event]) -> bool:
            hb.record(iterations=1)
            if hb.exhausted:
                # Budget exhausted: do not forward this event, stop pipe.
                return False
            await sender.send(item)
            return True

        return _async_pipe(ch, _process)

    return _apply  # type: ignore[return-value]


def logger_middleware(name: str = "superred.channels") -> Middleware[Event]:
    """Middleware that logs each event at DEBUG level, then forwards it."""
    log = logging.getLogger(name)

    def _apply(ch: Channel[Event]) -> Channel[Event]:
        async def _process(item: Event, sender: AsyncSender[Event]) -> bool:
            log.debug("channel event: %s", item)
            await sender.send(item)
            return True

        return _async_pipe(ch, _process)

    return _apply  # type: ignore[return-value]
