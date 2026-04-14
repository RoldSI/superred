"""Target self-description metadata.

Every target adapter carries metadata describing its capabilities
and observability tier.  The observability tier is critical because
claim strength and provenance guarantees depend on whether the
framework wraps an opaque API, an LLM-proxy-enabled system, or a
fully instrumented runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class TargetMetadata:
    """Static metadata for a target module.

    Attributes:
        target_id: Machine-readable identifier
            (e.g. ``"openclaw"``, ``"agentdojo"``).
        display_name: Human-readable name.
        version: Semantic version of the adapter.
        target_type: Category of the target.
        observability_tier: How deeply the framework can observe
            the target.  Determines what provenance and claims
            are defensible.

            - ``"base"``: opaque API, only input/output visible
            - ``"proxy"``: LLM and/or tool calls intercepted via proxy
            - ``"instrumented"``: full runtime telemetry available
        supports_parallel_runs: Whether concurrent run sessions
            are safe.
        supports_replay: Whether deterministic replay is possible.
        notes: Free-form notes for humans.
    """

    target_id: str
    display_name: str
    version: str = "0.1.0"
    target_type: Literal["real_system", "benchmark", "api_only", "dockerized"] = "real_system"
    observability_tier: Literal["base", "proxy", "instrumented"] = "base"
    supports_parallel_runs: bool = False
    supports_replay: bool = False
    notes: str = ""
