"""Replay proxy middleware: replays recorded responses up to a checkpoint."""

from __future__ import annotations

import asyncio

from superred.channels.channel import Channel, AsyncSender, channel
from superred.channels.middleware import Middleware
from superred.types.event import Event, EventResponse
from superred.types.trajectory import TrajectoryEntry


class ReplayDivergenceError(Exception):
    """Raised when the checkpoint is beyond the number of recorded entries."""

    def __init__(self, checkpoint: int, expected: TrajectoryEntry | None = None, got: Event | None = None):
        self.checkpoint = checkpoint
        self.expected = expected
        self.got = got
        super().__init__(f"Diverged at checkpoint {checkpoint}")


def replay_proxy(
    recorded_entries: list[TrajectoryEntry],
    recorded_responses: list[EventResponse],
    checkpoint: int,
) -> Middleware:
    """Middleware that replays recorded responses up to checkpoint.

    Events with index ``< checkpoint`` receive the corresponding
    ``recorded_responses[index]`` instead of flowing through live.
    Events with index ``>= checkpoint`` pass through unchanged.

    Raises :class:`ReplayDivergenceError` if *checkpoint* exceeds the
    number of recorded entries/responses available for replay.
    """
    if checkpoint > len(recorded_entries) or checkpoint > len(recorded_responses):
        raise ReplayDivergenceError(checkpoint)

    def _apply(ch: Channel[Event]) -> Channel[Event]:
        outer = channel[Event]()
        index = 0

        async def _run() -> None:
            nonlocal index
            try:
                async for item in ch.receiver:
                    if index < checkpoint:
                        # Replay: emit the recorded response instead of the live event
                        await outer.sender.send(recorded_responses[index])
                    else:
                        # Live: forward the event unchanged
                        await outer.sender.send(item)
                    index += 1
            except StopAsyncIteration:
                pass
            finally:
                outer.sender.close()

        asyncio.ensure_future(_run())
        return Channel(sender=ch.sender, receiver=outer.receiver)

    return _apply  # type: ignore[return-value]
