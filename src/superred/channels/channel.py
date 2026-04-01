"""Typed async channel with sender/receiver ends."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Generic, TypeVar, Self

T = TypeVar("T")

_SENTINEL = object()


class ChannelClosed(Exception):
    """Raised when sending to a closed channel."""


class AsyncSender(Generic[T]):
    """Write end of a channel."""

    def __init__(self, queue: asyncio.Queue[T | object]) -> None:
        self._queue = queue
        self._closed = False

    async def send(self, item: T) -> None:
        if self._closed:
            raise ChannelClosed("Cannot send to a closed channel")
        await self._queue.put(item)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._queue.put_nowait(_SENTINEL)


class AsyncReceiver(Generic[T]):
    """Read end of a channel. Supports async iteration."""

    def __init__(self, queue: asyncio.Queue[T | object]) -> None:
        self._queue = queue

    async def recv(self) -> T:
        item = await self._queue.get()
        if item is _SENTINEL:
            raise StopAsyncIteration
        return item  # type: ignore[return-value]

    def recv_nowait(self) -> T | None:
        try:
            item = self._queue.get_nowait()
        except asyncio.QueueEmpty:
            return None
        if item is _SENTINEL:
            self._queue.put_nowait(_SENTINEL)  # re-queue for other consumers
            return None
        return item  # type: ignore[return-value]

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> T:
        item = await self._queue.get()
        if item is _SENTINEL:
            raise StopAsyncIteration
        return item  # type: ignore[return-value]


@dataclass
class Channel(Generic[T]):
    """A typed, buffered, async pipe."""

    sender: AsyncSender[T]
    receiver: AsyncReceiver[T]


class channel(Channel[T]):
    """Create a channel pair.

    Supports subscript syntax for type hints: ``channel[str]()``.
    ``buffer=0`` means unbounded.
    """

    def __init__(self, buffer: int = 0) -> None:
        maxsize = buffer if buffer > 0 else 0
        q: asyncio.Queue[T | object] = asyncio.Queue(maxsize=maxsize)
        self.sender: AsyncSender[T] = AsyncSender(q)
        self.receiver: AsyncReceiver[T] = AsyncReceiver(q)

    def __class_getitem__(cls, item: type) -> type[channel]:  # type: ignore[override]
        """Allow ``channel[SomeType]`` subscript syntax (type erased at runtime)."""
        return cls
