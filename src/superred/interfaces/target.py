"""Abstract base class for evaluation targets."""

from __future__ import annotations

from abc import ABC, abstractmethod

from superred.channels.channel import AsyncReceiver, AsyncSender
from superred.types import (
    ConfigSpec,
    ControllableSpec,
    Event,
    EventResponse,
    Observable,
    ObservableValue,
    RuntimeParamSpec,
    StateSpec,
)


class Target(ABC):
    """A system under evaluation.

    Targets expose controllable points (where an optimizer can inject),
    observable state, configuration knobs, and a ``run`` coroutine that
    drives one interaction through the system.
    """

    # ------------------------------------------------------------------
    # Specification introspection
    # ------------------------------------------------------------------

    @abstractmethod
    def controllable_specs(self) -> list[ControllableSpec]:
        """Return the controllable-point specifications for this target."""
        ...

    @abstractmethod
    def observable_specs(self) -> list[Observable]:
        """Return the observable specifications for this target."""
        ...

    @abstractmethod
    def config_specs(self) -> list[ConfigSpec]:
        """Return configuration specifications the target accepts."""
        ...

    @abstractmethod
    def state_specs(self) -> list[StateSpec]:
        """Return state specifications the target exposes."""
        ...

    @abstractmethod
    def runtime_params(self) -> list[RuntimeParamSpec]:
        """Return runtime parameter specifications."""
        ...

    # ------------------------------------------------------------------
    # Configuration & observation
    # ------------------------------------------------------------------

    @abstractmethod
    async def set_config(self, name: str, value: str) -> None:
        """Apply a configuration value by name."""
        ...

    @abstractmethod
    async def get_observables(self) -> list[ObservableValue]:
        """Read current observable values from the target."""
        ...

    @abstractmethod
    async def get_state(self, name: str) -> str:
        """Read a named piece of target state."""
        ...

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    @abstractmethod
    async def run(
        self,
        send_event: AsyncSender[Event],
        recv_response: AsyncReceiver[EventResponse],
    ) -> None:
        """Execute one interaction, emitting events and receiving responses."""
        ...

    # ------------------------------------------------------------------
    # Lifecycle (optional overrides)
    # ------------------------------------------------------------------

    async def setup(self) -> None:
        """One-time initialisation (e.g. start a container)."""

    async def teardown(self) -> None:
        """Clean up resources after all runs are finished."""

    @property
    def max_concurrent_runs(self) -> int:
        """How many ``run()`` calls may execute in parallel. Default 1."""
        return 1
