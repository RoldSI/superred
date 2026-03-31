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
from superred.core.types.event import Event, EventResponse, OptimizerDoneEvent
from superred.core.types.goal import Goal
from superred.core.types.observable import ObservableValue
from superred.core.types.trajectory import Trajectory


class Optimizer(ABC):
    """Base class for all optimizers.

    Optimizers are event-driven: the framework dispatches events via
    :meth:`_handle_event` each time an event occurs during a target run.

    The base class maintains a full history of past runs so that optimizer
    implementations can query previous trajectories without any bookkeeping.

    Implementors override:
        - :meth:`initialize` — setup before the first run.
        - :meth:`on_event` — respond to each event during a run.
        - :meth:`on_pre_run` (optional) — called after trajectory is set,
          before the target starts.
        - :meth:`on_post_run` (optional) — called after the run ends, before
          the trajectory is archived. Return an :class:`OptimizerDoneEvent`
          to signal the optimizer is finished.

    Lifecycle:
        1. Instantiate with configuration.
        2. Call :meth:`initialize` with goal, controllables, observables.
        3. For each run:
            a. Framework calls :meth:`_on_run_start` (sets trajectory,
               then calls :meth:`on_pre_run`).
            b. For each event: framework calls :meth:`_handle_event`.
            c. Framework calls :meth:`_on_run_end` (calls :meth:`on_post_run`,
               then archives trajectory). Returns OptimizerDoneEvent | None.
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
    # Run lifecycle — internal (called by framework)
    # ------------------------------------------------------------------

    def _on_run_start(self, trajectory: Trajectory) -> None:
        """Framework-facing: set trajectory then call :meth:`on_pre_run`.

        Do not override. Override :meth:`on_pre_run` instead.
        """
        self._current_trajectory = trajectory
        self.pre_run()

    def _on_run_end(self) -> OptimizerDoneEvent | None:
        """Framework-facing: call :meth:`on_post_run` then archive trajectory.

        Do not override. Override :meth:`on_post_run` instead.

        Returns:
            An :class:`OptimizerDoneEvent` if the optimizer signals it is
            done, or ``None`` to continue.
        """
        assert self._current_trajectory is not None, "_on_run_end called without an active run"
        done = self.post_run()
        self._past_trajectories.append(self._current_trajectory)
        self._current_trajectory = None
        return done

    # ------------------------------------------------------------------
    # Run lifecycle — overridable hooks
    # ------------------------------------------------------------------

    def pre_run(self) -> None:
        """Called after the trajectory is set, before the target starts.

        The current trajectory is available via :attr:`current_trajectory`.
        Override for custom pre-run logic.
        """

    def post_run(self) -> OptimizerDoneEvent | None:
        """Called after the run ends, before the trajectory is archived.

        The current trajectory is still available via
        :attr:`current_trajectory`.

        Returns:
            An :class:`OptimizerDoneEvent` to signal the optimizer is
            finished (goal achieved, budget exhausted, etc.), or ``None``
            to continue with more runs.
        """
        return None

    # ------------------------------------------------------------------
    # Event handler (the main interface to implement)
    # ------------------------------------------------------------------

    @abstractmethod
    async def on_event(self, event: Event) -> EventResponse:
        """Respond to an event from the target system.

        Called each time an event occurs during a run. Use ``isinstance``
        to dispatch on event type::

            if isinstance(event, ControllablePreCallEvent):
                ...  # return ControllableInjection(event=event, value=...)
            elif isinstance(event, ControllablePostCallEvent):
                ...  # return ControllableInjection(event=event, value=...)

        The current trajectory is available via :attr:`current_trajectory`.

        Args:
            event: The typed event to respond to.

        Returns:
            A response whose type matches the event type.
        """
        ...

    async def _handle_event(self, event: Event) -> EventResponse:
        """Framework-facing wrapper around :meth:`on_event`.

        Do not override this method.
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
