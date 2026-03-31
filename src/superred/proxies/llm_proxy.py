"""LLM proxy middleware: records model request/response events to trajectory."""

from __future__ import annotations

from superred.channels.channel import Channel, AsyncSender, channel
from superred.channels.middleware import Middleware, _async_pipe
from superred.types.event import Event, ControllablePreCallEvent, ControllablePostCallEvent
from superred.types.trajectory import Trajectory, TrajectoryEntry, MODEL_REQUEST, MODEL_RESPONSE
from superred.types.budget import HierarchicalBudget


def llm_proxy(trajectory: Trajectory, budget: HierarchicalBudget | None = None) -> Middleware:
    """Middleware that records LLM calls to trajectory and optionally tracks cost.

    Intercepts :class:`ControllablePreCallEvent` (model request) and
    :class:`ControllablePostCallEvent` (model response) events, writes
    corresponding trajectory entries, and forwards all events unchanged.

    When *budget* is provided, each post-call event increments the
    ``model_calls`` counter on the budget.
    """

    def _apply(ch: Channel[Event]) -> Channel[Event]:
        async def _process(item: Event, sender: AsyncSender[Event]) -> bool:
            if isinstance(item, ControllablePreCallEvent):
                entry = TrajectoryEntry(
                    entry_type=MODEL_REQUEST,
                    content=item.request,
                    security_domain=item.security_domain,
                )
                await trajectory.emit(entry)
            elif isinstance(item, ControllablePostCallEvent):
                entry = TrajectoryEntry(
                    entry_type=MODEL_RESPONSE,
                    content=item.answer,
                    security_domain=item.security_domain,
                )
                await trajectory.emit(entry)
                if budget is not None:
                    budget.record(model_calls=1)
            # Always forward
            await sender.send(item)
            return True

        return _async_pipe(ch, _process)

    return _apply  # type: ignore[return-value]
