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
from superred.core.types.state import ConfigSpec, ManualSpec, QuerySpec
from superred.core.types.trajectory import Trajectory

# The callback the target uses to send events and receive responses.
EventHandler = Callable[[Event], Awaitable[EventResponse]]


class Target(ABC):
    """Base class for all targets (AI systems under test).

    Implementors override:
        - :attr:`manual_specs` — declare required user-provided values.
        - :meth:`set_manual` — accept all user-provided values.
        - :attr:`config_specs` — declare pre-run configuration slots.
        - :meth:`set_config` — accept a configuration value.
        - :attr:`query_specs` — declare post-run interactions.
        - :meth:`query` — execute a post-run query.
        - :meth:`get_controllables` — declare runtime injection points.
        - :meth:`get_observables` — provide static context.
        - :meth:`run` — execute one run.
        - :meth:`teardown` — release resources.
    """

    # ------------------------------------------------------------------
    # Manual setup (user provides these via the controller)
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def manual_specs(self) -> list[ManualSpec]:
        """Values that must be provided by the user (e.g. API keys).

        These are not set by tasks — they are provided by the user
        through the controller before any runs.
        """
        ...

    @abstractmethod
    def set_manual(self, values: dict[str, str]) -> None:
        """Submit all user-provided values at once.

        Args:
            values: A dict mapping :attr:`ManualSpec.name` to its value.
                Must include all names from :attr:`manual_specs`.
        """
        ...

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
    # Post-run queries (evaluator uses these after a run)
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def query_specs(self) -> list[QuerySpec]:
        """Interactions available after a run.

        Each spec declares a named query the evaluator can call,
        optionally with parameters. These are distinct from config specs.
        """
        ...

    @abstractmethod
    def query(self, name: str, **params: str) -> str:
        """Execute a post-run query.

        May be a simple getter (no params) or an action with parameters.

        Args:
            name: Must match a :attr:`QuerySpec.name` from :attr:`query_specs`.
            **params: Keyword arguments matching the spec's params.

        Returns:
            The text result of the query.
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

    @abstractmethod
    async def teardown(self) -> None:
        """Release resources. Called after evaluation is done."""
        ...
