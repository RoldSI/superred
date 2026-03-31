"""Target module interface (Interface A — target side).

A target module wraps an AI system into a standardised interface, hiding all
details of how the system runs (locally, Docker, remote API, etc.).  It
exposes the full attack surface for the strongest possible attacker; the
controller restricts access via threat models.

At runtime the target module opens a **run session** via ``open_run()``.
The session exposes a step-based interaction loop with controllables,
observables, and a canonical trace.

Plugin authors implement classes that conform to :class:`TargetModuleInterface`
and :class:`TargetRunInterface`.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Protocol, Sequence, runtime_checkable

from superred.core.types.context import TurnResult
from superred.core.types.threat_model import (
    InterfaceSpec,
    RuntimeParamSpec,
    TargetMetadata,
    ThreatModel,
)
from superred.core.types.trajectory import TraceEvent


@runtime_checkable
class TargetRunInterface(Protocol):
    """Session interface for a single evaluation run against a target.

    Obtained from :meth:`TargetModuleInterface.open_run`.  The controller
    (or bound task) drives the run by applying controllables, stepping, and
    reading the trace.
    """

    def threat_model(self) -> ThreatModel: ...

    def available_controllables(self) -> Sequence[InterfaceSpec]: ...

    def available_observables(self) -> Sequence[InterfaceSpec]: ...

    def apply_controllables(self, values: Mapping[str, Any]) -> None: ...

    def step(self) -> TurnResult: ...

    def trace(self) -> Sequence[TraceEvent]: ...

    def close(self) -> None: ...


@runtime_checkable
class TargetModuleInterface(Protocol):
    """Strongest-exposure wrapper around a target system.

    Describes what the system can expose in principle — controllables,
    observables, runtime requirements, and how to open a run session.
    The controller restricts access via threat models at ``open_run`` time.
    """

    def metadata(self) -> TargetMetadata: ...

    def controllables(self) -> Sequence[InterfaceSpec]: ...

    def observables(self) -> Sequence[InterfaceSpec]: ...

    def feedback_channels(self) -> Sequence[InterfaceSpec]: ...

    def runtime_params(self) -> Sequence[RuntimeParamSpec]: ...

    def open_run(
        self,
        *,
        threat_model: ThreatModel,
        runtime_params: Mapping[str, Any],
    ) -> TargetRunInterface: ...
