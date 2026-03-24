"""Target module interface (Interface B — target side).

A target module wraps an AI system into a standardized interface, hiding all
details of how the system runs (locally, Docker, remote API, etc.). It exposes
the full attack surface for the strongest possible attacker; the controller
restricts access via threat models.

At runtime the target module acts as a **generator**: each run yields trace
events as they occur, enabling both streaming processing and wait-for-completion
usage by optimizers.

Plugin authors implement this ABC. The controller validates conformance at
load time via ``issubclass(cls, TargetModuleInterface)``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Any

from superred.core.types.controllable import Controllable, ControllableValue
from superred.core.types.observable import ObservableSpec, StaticObservable
from superred.core.types.threat_model import SecurityTag
from superred.core.types.trajectory import TraceEvent, Trajectory


class TargetModuleInterface(ABC):
    """Abstract interface that every target module must implement.

    A target module is a wrapper around an AI system that:
    1. Declares its full interface set (controllables + observables).
    2. Runs the system with injected controllable values.
    3. Yields trace events as a generator during execution.

    Lifecycle:
        1. Instantiate with configuration.
        2. Call :meth:`get_controllables` / :meth:`get_observables` /
           :meth:`get_static_observables` to discover the interface set.
        3. Call :meth:`run` with controllable values; iterate to receive events.
        4. Call :meth:`reset` between runs if needed.
        5. Call :meth:`teardown` when done.
    """

    # ------------------------------------------------------------------
    # Interface discovery
    # ------------------------------------------------------------------

    @abstractmethod
    def get_controllables(self) -> list[Controllable]:
        """Return all controllables (attack surfaces) this target exposes.

        Each controllable is tagged with a security domain. The controller
        filters these by threat model before passing them to the optimizer.
        """
        ...

    @abstractmethod
    def get_observable_specs(self) -> list[ObservableSpec]:
        """Return specifications of all dynamic observables this target produces.

        Dynamic observables are trace events emitted during :meth:`run`.
        """
        ...

    @abstractmethod
    def get_static_observables(self) -> list[StaticObservable]:
        """Return static observables available before any run.

        Examples: system description, source code, configuration files.
        Each is tagged with a security domain for threat model filtering.
        """
        ...

    @abstractmethod
    def get_security_tags(self) -> frozenset[SecurityTag]:
        """Return all security domain tags used by this target module.

        Includes both standard and any target-specific custom tags.
        """
        ...

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    @abstractmethod
    def run(self, controllable_values: list[ControllableValue]) -> Iterator[TraceEvent]:
        """Execute the target system with the given controllable values injected.

        This is a **generator** that yields :class:`TraceEvent` objects as the
        target system executes. The optimizer may consume events as they arrive
        (event-loop style) or collect them all (wait for iterator exhaustion).

        The final state after exhaustion constitutes the complete trajectory
        for this run.

        Args:
            controllable_values: Values to inject at the declared controllables.
                Names must match :attr:`ControllableSpec.name` from
                :meth:`get_controllables`.

        Yields:
            Trace events in chronological order.
        """
        ...

    # ------------------------------------------------------------------
    # Lifecycle — with backward-compatible defaults
    # ------------------------------------------------------------------

    def reset(self) -> None:
        """Reset the target module state between runs.

        Override if the target needs cleanup between optimization iterations
        (e.g. clearing Docker state, resetting databases).
        """

    def teardown(self) -> None:
        """Release all resources held by the target module.

        Called once when the evaluation is complete. Override for cleanup of
        Docker containers, network connections, temporary files, etc.
        """

    # ------------------------------------------------------------------
    # Optional capabilities — v2 extensions with defaults
    # ------------------------------------------------------------------

    def supports_parallel(self) -> bool:
        """Whether this target supports running multiple instances concurrently.

        If True, the controller may queue multiple runs in parallel for
        optimizers that can exploit parallelism.
        """
        return False

    def max_parallel_instances(self) -> int:
        """Maximum number of concurrent instances, if :meth:`supports_parallel` is True."""
        return 1

    def get_run_trajectory(self) -> Trajectory | None:
        """Return the complete trajectory of the most recent run.

        Convenience method that returns the assembled trajectory after a run
        completes, rather than requiring the caller to collect events manually.
        Returns None if no run has been executed.
        """
        return None

    def get_metadata(self) -> dict[str, Any]:
        """Return target module metadata for discovery and documentation.

        May include name, version, description, author, supported features, etc.
        """
        return {}
