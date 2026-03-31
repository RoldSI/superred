"""Target interface.

A target is the AI system under test. It exposes controllables (injection
points) and observables (static context), and can be run against a trajectory.

During a run the target calls ``send_event`` at each controllable point,
pausing until it receives a response. This is the synchronous event-response
loop shown in the architecture diagram.

Target authors implement this ABC.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable

from superred.core.types.controllable import Controllable
from superred.core.types.event import Event, EventResponse
from superred.core.types.observable import ObservableValue
from superred.core.types.trajectory import Trajectory

# The callback the target uses to send events and receive responses.
EventHandler = Callable[[Event], Awaitable[EventResponse]]


class Target(ABC):
    """Base class for all targets (AI systems under test).

    Implementors override:
        - :meth:`get_controllables` — declare injection points.
        - :meth:`get_observables` — provide static context about the system.
        - :meth:`run` — execute one run of the target system.
    """

    @abstractmethod
    def get_controllables(self) -> list[Controllable]:
        """Return the controllables (injection points) this target exposes."""
        ...

    @abstractmethod
    def get_observables(self) -> list[ObservableValue]:
        """Return static observables describing this target system."""
        ...

    @abstractmethod
    async def run(
        self,
        trajectory: Trajectory,
        send_event: EventHandler,
    ) -> None:
        """Execute one run of the target system.

        The target emits trajectory entries via ``trajectory.emit()`` and
        pauses at controllable points by calling ``send_event(event)`` to
        get the optimizer's response.

        Args:
            trajectory: The trajectory to emit entries into.
            send_event: Callback to send an event and await a response.
                The target calls this at each controllable point and uses
                the returned :class:`EventResponse` to continue execution.
        """
        ...
