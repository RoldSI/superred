"""Staged runner: resumes evaluation from a checkpoint using replay."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from superred.types.trajectory import Trajectory, TrajectoryEntry
from superred.types.event import EventResponse
from superred.controller.results import RunResult


class StagedRunner:
    """Runs an evaluation from a checkpoint using recorded trajectory entries.

    The staged runner combines the replay proxy with a live evaluation
    to skip past already-explored trajectory prefixes. This enables
    efficient search-tree exploration by reusing prior work up to a
    divergence point.
    """

    def __init__(self) -> None:
        self._prior_entries: list[TrajectoryEntry] = []
        self._prior_responses: list[EventResponse] = []
        self._checkpoint: int = 0

    def set_replay_data(
        self,
        entries: list[TrajectoryEntry],
        responses: list[EventResponse],
        checkpoint: int,
    ) -> None:
        """Configure the replay data and checkpoint for the next run."""
        self._prior_entries = list(entries)
        self._prior_responses = list(responses)
        self._checkpoint = checkpoint

    @property
    def checkpoint(self) -> int:
        return self._checkpoint

    @property
    def prior_entries(self) -> list[TrajectoryEntry]:
        return list(self._prior_entries)

    @property
    def prior_responses(self) -> list[EventResponse]:
        return list(self._prior_responses)

    async def run_from_checkpoint(
        self,
        prior_trajectory: Trajectory,
        checkpoint: int,
        optimizer: Any = None,
        target: Any = None,
        threat_model: Any = None,
    ) -> RunResult | None:
        """Run evaluation from a checkpoint.

        This is a skeleton for the full staged-run implementation.
        The replay proxy will be wired into the channel stack to skip
        past the first *checkpoint* events, then switch to live execution.

        Returns None until fully wired (placeholder).
        """
        self._checkpoint = checkpoint
        self._prior_entries = prior_trajectory.snapshot()[:checkpoint]
        # Full implementation will wire replay_proxy into the channel stack
        # and delegate to Controller.run() with the modified middleware.
        return None
