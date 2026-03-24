"""Observable specifications and static observables.

Observables are the information the optimizer receives about the target system.
They come in two forms:

1. **Dynamic observables** — trajectory events streamed during a run, filtered
   by the threat model's projection operator O(M, T).
2. **Static observables** — information available before any run (system
   description, code, configuration), also filtered by threat model tags.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from superred.core.types.threat_model import SecurityTag


@dataclass(frozen=True)
class ObservableSpec:
    """Specification of an observable information source.

    Attributes:
        name: Unique identifier within the target module.
        security_tag: Security domain this observable belongs to.
        description: Human-readable description.
        observable_type: Type of information ("trajectory", "static_text",
            "static_code", "static_config", "static_json").
        metadata: Additional target-specific metadata.
    """

    name: str
    security_tag: SecurityTag
    description: str = ""
    observable_type: str = "trajectory"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StaticObservable:
    """A static observable with its spec and content.

    Static observables are available before execution and don't change between
    runs (e.g. system description, source code, configuration).
    """

    spec: ObservableSpec
    content: Any = None
