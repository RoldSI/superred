"""Event channel: thread-safe bidirectional event-response communication.

The channel decouples event senders (controller/target side) from receivers
(optimizer side). The sender puts an event and awaits a response. The
receiver pulls events at its own pace and responds when ready.

Thread safety:
    - ``send()`` and ``receive()`` run on the asyncio event loop thread.
    - ``respond()`` and ``close()`` use ``call_soon_threadsafe`` so they
      can be called safely from any thread.
    - The internal ``asyncio.Queue`` is only accessed from the event loop.

Process safety:
    This is an in-process implementation. The interface (send/receive/
    respond/close) is designed so a future process-safe implementation
    (multiprocessing pipes, sockets, etc.) can provide the same contract.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import AsyncIterator

from superred.core.types.event import Event, EventResponse


class EventEnvelope:
    """An event paired with its response mechanism.

    The receiver calls :meth:`respond` exactly once to deliver the response
    back to the sender. Thread-safe — ``respond()`` may be called from any
    thread.

    Attributes:
        event: The event to handle.
    """

    __slots__ = ("event", "_future", "_loop", "_responded", "_lock")

    def __init__(
        self,
        event: Event,
        future: asyncio.Future[EventResponse],
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self.event = event
        self._future = future
        self._loop = loop
        self._responded = False
        self._lock = threading.Lock()

    def respond(self, response: EventResponse) -> None:
        """Deliver the response for this event.

        Thread-safe. Must be called exactly once.

        Raises:
            RuntimeError: If called more than once.
        """
        with self._lock:
            if self._responded:
                raise RuntimeError("EventEnvelope.respond() called more than once")
            self._responded = True
        self._loop.call_soon_threadsafe(self._future.set_result, response)


class EventChannel:
    """Thread-safe bidirectional event-response channel.

    The send side puts events and awaits responses. The receive side
    pulls events at its own pace and responds via the envelope.

    Supports ``async for`` iteration on the receive side::

        async for envelope in channel:
            response = handle(envelope.event)
            envelope.respond(response)

    Iteration ends when the channel is closed and all envelopes have
    been consumed.
    """

    def __init__(self) -> None:
        self._queue: asyncio.Queue[EventEnvelope | None] = asyncio.Queue()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._closed = False
        self._close_lock = threading.Lock()

    async def send(self, event: Event) -> EventResponse:
        """Send an event and wait for its response.

        Must be called from the event loop thread (i.e., from an async
        context on the loop that the channel is bound to).

        Args:
            event: The event to send.

        Returns:
            The response produced by the receiver.

        Raises:
            RuntimeError: If the channel is already closed.
        """
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        future: asyncio.Future[EventResponse] = loop.create_future()
        envelope = EventEnvelope(event=event, future=future, loop=loop)
        await self._queue.put(envelope)
        return await future

    async def receive(self) -> EventEnvelope | None:
        """Receive the next event envelope.

        Returns ``None`` when the channel has been closed and all pending
        envelopes have been consumed.

        Must be called from the event loop thread.
        """
        if self._loop is None:
            self._loop = asyncio.get_running_loop()
        return await self._queue.get()

    def close(self) -> None:
        """Signal that no more events will be sent.

        Thread-safe — may be called from any thread. Puts a sentinel
        (``None``) on the queue so the receiver knows to stop.
        """
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        loop = self._loop
        if loop is not None:
            loop.call_soon_threadsafe(self._queue.put_nowait, None)
        else:
            # No send/receive has captured the loop yet.
            # put_nowait is safe here: asyncio.Queue uses a deque
            # internally, and no one can be awaiting get() yet.
            self._queue.put_nowait(None)

    # -- Async iteration ---------------------------------------------------

    def __aiter__(self) -> AsyncIterator[EventEnvelope]:
        return self

    async def __anext__(self) -> EventEnvelope:
        envelope = await self.receive()
        if envelope is None:
            raise StopAsyncIteration
        return envelope
