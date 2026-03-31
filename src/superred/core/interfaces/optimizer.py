"""Optimizer interface.

An optimizer is an event-driven agent that responds to events emitted by the
target system during a run. The framework calls the optimizer's event handler
with each event and the current run's trajectory stream. The optimizer reads
the trajectory to understand what has happened, then returns a response.

Optimizers form a tree/graph: a meta-optimizer can delegate to sub-optimizers,
each of which may further delegate. This enables modular composition.

Optimizer authors implement this ABC.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from superred.core.types.controllable import Controllable
from superred.core.types.event import Event, EventResponse
from superred.core.types.goal import Goal
from superred.core.types.observable import ObservableValue
from superred.core.types.trajectory import Trajectory


class Optimizer(ABC):
    """Base class for all optimizers.

    Optimizers are event-driven: the framework calls :meth:`handle_event`
    each time an event occurs during a target run. The optimizer reads the
    live trajectory stream to understand the current run state, then returns
    a response.

    The base class maintains a full history of past runs so that optimizer
    implementations can query previous trajectories without any bookkeeping.
    Implementors only need to override :meth:`on_event`.

    Lifecycle:
        1. Instantiate with configuration.
        2. Call :meth:`initialize` with goal, controllables, observables.
        3. For each run:
            a. Call :meth:`on_run_start` with the new trajectory.
            b. For each event: call :meth:`handle_event`.
            c. Call :meth:`on_run_end` when the run completes.
        4. Call :meth:`teardown` when evaluation is done.
    """

    def __init__(self) -> None:
        self._past_trajectories: list[Trajectory] = []
        self._current_trajectory: Trajectory | None = None

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    @abstractmethod
    async def initialize(
        self,
        goal: Goal,
        controllables: list[Controllable],
        observables: list[ObservableValue],
    ) -> None:
        """Set up the optimizer before the first run.

        Args:
            goal: The adversarial goal.
            controllables: Available injection points.
            observables: Global observables describing the target system.
        """
        ...

    # ------------------------------------------------------------------
    # Run lifecycle hooks (called by framework)
    # ------------------------------------------------------------------

    def on_run_start(self, trajectory: Trajectory) -> None:
        """Called by the framework when a new run begins.

        Stores the trajectory as the current run. Override to add custom
        logic, but call ``super().on_run_start(trajectory)`` to preserve
        history tracking.
        """
        self._current_trajectory = trajectory

    def on_run_end(self) -> None:
        """Called by the framework when the current run ends.

        Moves the current trajectory to history. Override to add custom
        logic, but call ``super().on_run_end()`` to preserve history tracking.

        Raises:
            AssertionError: If no run is currently active.
        """
        assert self._current_trajectory is not None, "on_run_end called without an active run"
        self._past_trajectories.append(self._current_trajectory)
        self._current_trajectory = None

    # ------------------------------------------------------------------
    # Event handler (the main interface to implement)
    # ------------------------------------------------------------------

    @abstractmethod
    async def on_event(self, event: Event) -> EventResponse:
        """Respond to an event from the target system.

        Called each time an event occurs during a run. Use ``isinstance``
        to dispatch on event type::

            if isinstance(event, ControllablePreCallEvent):
                ...  # return ControllablePreCallResponse(value=...)
            elif isinstance(event, ControllablePostCallEvent):
                ...  # return ControllablePostCallResponse()

        The current trajectory is available via :attr:`current_trajectory`.

        Args:
            event: The typed event to respond to.

        Returns:
            A response whose type matches the event type.
        """
        ...

    async def _handle_event(self, event: Event) -> EventResponse:
        """Framework-facing wrapper around :meth:`on_event`.

        Handles base-class bookkeeping and delegates to the optimizer's
        :meth:`on_event` implementation. Do not override this method.
        """
        return await self.on_event(event)

    # ------------------------------------------------------------------
    # History utilities
    # ------------------------------------------------------------------

    @property
    def past_trajectories(self) -> list[Trajectory]:
        """All completed run trajectories, oldest first."""
        return list(self._past_trajectories)

    @property
    def current_trajectory(self) -> Trajectory | None:
        """The trajectory for the currently active run, or None between runs."""
        return self._current_trajectory

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def teardown(self) -> None:
        """Release resources. Override for cleanup."""

    def get_metadata(self) -> dict[str, Any]:
        """Return optimizer metadata for discovery and documentation.

        Include a ``"name"`` key to set the optimizer's display name.
        Default: ``{"name": <class name>}``.
        """
        return {"name": self.__class__.__name__}
