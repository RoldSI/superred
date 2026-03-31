"""Abstract base class for optimizers (attack strategies)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from superred.channels.channel import AsyncReceiver, AsyncSender
from superred.types import (
    Controllable,
    Event,
    EventResponse,
    Goal,
    ObservableValue,
    OptimizerDoneEvent,
    PassThrough,
    Trajectory,
)
from superred.types.budget import HierarchicalBudget


class Optimizer(ABC):
    """An attack strategy that responds to target events.

    The controller drives the optimizer through ``initialize`` then repeated
    ``on_event`` calls. The optimizer tracks the current and past trajectories
    for its own bookkeeping.
    """

    def __init__(self) -> None:
        self._past_trajectories: list[Trajectory] = []
        self._current_trajectory: Trajectory | None = None

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abstractmethod
    async def initialize(
        self,
        goal: Goal,
        controllables: list[Controllable],
        observables: list[ObservableValue],
        budget: HierarchicalBudget,
    ) -> None:
        """Set up the optimizer with the goal, controls, and budget."""
        ...

    @abstractmethod
    async def on_event(self, event: Event) -> EventResponse | None:
        """React to a target event. Return ``None`` to pass through."""
        ...

    # ------------------------------------------------------------------
    # Optional lifecycle hooks
    # ------------------------------------------------------------------

    async def pre_run(self) -> None:
        """Called before each run begins."""

    async def post_run(self) -> OptimizerDoneEvent | None:
        """Called after each run ends. May signal done."""
        return None

    async def teardown(self) -> None:
        """Clean up any optimizer resources."""

    def get_metadata(self) -> dict[str, Any]:
        """Return arbitrary metadata about the optimizer."""
        return {}

    # ------------------------------------------------------------------
    # Trajectory tracking (called by the controller)
    # ------------------------------------------------------------------

    def _on_run_start(self, trajectory: Trajectory) -> None:
        self._current_trajectory = trajectory

    def _on_run_end(self) -> OptimizerDoneEvent | None:
        if self._current_trajectory is not None:
            self._past_trajectories.append(self._current_trajectory)
        self._current_trajectory = None
        # Note: post_run() is async and must be called separately by the controller
        return None

    # ------------------------------------------------------------------
    # Internal run loop (used by the controller to wire channels)
    # ------------------------------------------------------------------

    async def _run_loop(
        self,
        event_rx: AsyncReceiver[Event],
        response_tx: AsyncSender[EventResponse],
    ) -> None:
        async for event in event_rx:
            response = await self.on_event(event)
            if response is not None:
                await response_tx.send(response)
            else:
                await response_tx.send(PassThrough(event=event))

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def current_trajectory(self) -> Trajectory | None:
        return self._current_trajectory

    @property
    def past_trajectories(self) -> list[Trajectory]:
        return list(self._past_trajectories)
