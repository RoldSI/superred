"""Controllable specifications, values, and modifiers.

Controllables are the attack surfaces exposed by a target module. Each
controllable is tagged with a security domain and represents an injection point
that the optimizer can manipulate.

A controllable may be simple (e.g. a user input string) or complex (e.g. a
database that returns modified content based on query context). Complex
controllables are handled via :class:`Modifier` — a callable that receives
request context and history and decides how to act.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from superred.core.types.threat_model import SecurityTag


@dataclass(frozen=True)
class ControllableSpec:
    """Specification of a single controllable (attack surface).

    Attributes:
        name: Unique identifier within the target module.
        security_tag: Security domain this controllable belongs to.
        description: Human-readable description of the injection point.
        value_type: Expected type of the controllable value ("text", "json",
            "modifier", "binary").
        required: Whether the optimizer must provide a value for this
            controllable on every run (vs. leaving it at default).
        metadata: Additional target-specific metadata.
    """

    name: str
    security_tag: SecurityTag
    description: str = ""
    value_type: str = "text"
    required: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Controllable:
    """A controllable with its spec and current default value.

    Returned by the target module to describe what can be controlled.
    """

    spec: ControllableSpec
    default_value: Any = None


@dataclass
class ControllableValue:
    """A concrete value assigned to a controllable by the optimizer.

    Attributes:
        name: Must match a :attr:`ControllableSpec.name`.
        value: The value to inject. For simple controllables this is a string
            or structured data. For complex ones, this is a :class:`Modifier`.
    """

    name: str
    value: Any


# Type alias for modifier functions.
# A modifier receives (request_context, request_history) and returns the
# modified/injected content. This handles complex injection points like
# databases where output depends on the query.
ModifierContext = dict[str, Any]
ModifierHistory = list[dict[str, Any]]
Modifier = Callable[[ModifierContext, ModifierHistory], Any]
