"""Tool proxy middleware: records tool call/result events to trajectory."""

from __future__ import annotations

from superred.channels.channel import Channel, AsyncSender, channel
from superred.channels.middleware import Middleware, _async_pipe
from superred.types.event import Event, ControllablePreCallEvent, ControllablePostCallEvent
from superred.types.trajectory import Trajectory, TrajectoryEntry, TOOL_CALL, TOOL_RESULT


def tool_proxy(trajectory: Trajectory) -> Middleware:
    """Middleware that records tool calls to trajectory.

    Intercepts :class:`ControllablePreCallEvent` (tool call) and
    :class:`ControllablePostCallEvent` (tool result) events, writes
    corresponding trajectory entries, and forwards all events unchanged.
    """

    def _apply(ch: Channel[Event]) -> Channel[Event]:
        async def _process(item: Event, sender: AsyncSender[Event]) -> bool:
            if isinstance(item, ControllablePreCallEvent):
                await trajectory.emit(TrajectoryEntry(
                    entry_type=TOOL_CALL,
                    content=item.request,
                    security_domain=item.security_domain,
                ))
            elif isinstance(item, ControllablePostCallEvent):
                await trajectory.emit(TrajectoryEntry(
                    entry_type=TOOL_RESULT,
                    content=item.answer,
                    security_domain=item.security_domain,
                ))
            # Always forward
            await sender.send(item)
            return True

        return _async_pipe(ch, _process)

    return _apply  # type: ignore[return-value]
