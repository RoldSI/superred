"""Broadcast EventBus: one publisher, many subscribers."""

from __future__ import annotations
from typing import Generic, TypeVar
from superred.channels.channel import channel, AsyncSender, AsyncReceiver

T = TypeVar("T")


class EventBus(Generic[T]):
    """Broadcast: one sender, many receivers. Each receiver gets a copy."""

    def __init__(self) -> None:
        self._senders: list[AsyncSender[T]] = []
        self._receivers: list[AsyncReceiver[T]] = []

    def __class_getitem__(cls, item):  # type: ignore[override]
        return cls  # runtime type erasure

    def subscribe(self) -> AsyncReceiver[T]:
        ch = channel[T]()
        self._senders.append(ch.sender)
        return ch.receiver

    async def publish(self, item: T) -> None:
        for sender in self._senders:
            await sender.send(item)

    def close(self) -> None:
        for sender in self._senders:
            sender.close()
