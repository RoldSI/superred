"""Target interface.

A target is the AI system under test. It exposes configuration slots
(for task setup), queryable state (for evaluation), controllables
(runtime injection points), and observables (static context).

During a run the target calls ``send_event`` at each controllable point,
pausing until it receives a response.

Target authors implement this ABC.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable

from superred.core.types.controllable import Controllable
from superred.core.types.event import Event, EventResponse
from superred.core.types.observable import ObservableValue
from superred.core.types.state import ConfigSpec, StateSpec
from superred.core.types.trajectory import Trajectory

# The callback the target uses to send events and receive responses.
EventHandler = Callable[[Event], Awaitable[EventResponse]]


class Target(ABC):
    """Base class for all targets (AI systems under test).

    Implementors override:
        - :attr:`config_specs` — declare pre-run configuration slots.
        - :meth:`set_config` — accept a configuration value.
        - :attr:`state_specs` — declare post-run queryable state.
        - :meth:`get_state` — return a state value for evaluation.
        - :meth:`get_controllables` — declare runtime injection points.
        - :meth:`get_observables` — provide static context.
        - :meth:`run` — execute one run.
    """

    # ------------------------------------------------------------------
    # Pre-run configuration (task sets these before a run)
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def config_specs(self) -> list[ConfigSpec]:
        """Configuration slots this target accepts.

        Each spec declares a named, text-valued slot. The description
        documents the expected format — that is the contract.
        """
        ...

    @abstractmethod
    def set_config(self, name: str, value: str) -> None:
        """Set a configuration value before a run.

        Args:
            name: Must match a :attr:`ConfigSpec.name` from :attr:`config_specs`.
            value: Text value in the format the spec's description expects.
        """
        ...

    # ------------------------------------------------------------------
    # Post-run state (evaluator queries these after a run)
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def state_specs(self) -> list[StateSpec]:
        """Queryable state available after a run.

        Each spec declares a named state that the evaluator can query
        for ground-truth evaluation. These are distinct from config specs.
        """
        ...

    @abstractmethod
    def get_state(self, name: str) -> str:
        """Query a state value after a run.

        Args:
            name: Must match a :attr:`StateSpec.name` from :attr:`state_specs`.

        Returns:
            The current text value of that state.
        """
        ...

    # ------------------------------------------------------------------
    # Controllables and observables
    # ------------------------------------------------------------------

    @abstractmethod
    def get_controllables(self) -> list[Controllable]:
        """Return the controllables (injection points) this target exposes."""
        ...

    @abstractmethod
    def get_observables(self) -> list[ObservableValue]:
        """Return static observables describing this target system."""
        ...

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

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
        """
        ...
