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


@dataclass(frozen=True)
class ControllableSpec:
    """Specification of a single controllable (attack surface).

    Attributes:
        name: Unique identifier within the target module.
        domains: Security domains this controllable belongs to.
        description: Human-readable description of the injection point.
        value_type: Expected type of the controllable value.
        required: Whether the optimizer must provide a value on every run.
        metadata: Additional target-specific metadata.
    """

    name: str
    domains: frozenset[str]
    description: str = ""
    value_type: str = "text"
    required: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Controllable:
    """A controllable with its spec and current default value."""

    spec: ControllableSpec
    default_value: Any = None


@dataclass
class ControllableValue:
    """A concrete value assigned to a controllable by the optimizer."""

    name: str
    value: Any


ModifierContext = dict[str, Any]
ModifierHistory = list[dict[str, Any]]
Modifier = Callable[[ModifierContext, ModifierHistory], Any]
