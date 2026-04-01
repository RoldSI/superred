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

from superred.core.types.security_domain import SecurityDomainTag


@dataclass(frozen=True)
class ControllableSpec:
    """Specification of a single controllable (attack surface).

    Attributes:
        name: Unique identifier within the target module.
        description: Human-readable description of the injection point.
        value_type: Expected type of the controllable value ("text", "json",
            "modifier", "binary").
    """

    name: str
    security_domain: SecurityDomainTag
    description: str = ""
    value_type: str = "text"


@dataclass(frozen=True)
class RequestAnswerPair:
    """A single request-answer interaction with a controllable.

    Attributes:
        request: The request made to the controllable.
        answer: The answer produced (possibly injected).
    """

    request: str
    answer: str


@dataclass
class Controllable:
    """A controllable attack surface exposed by the target.

    Tracks the history of request-answer interactions during runs.

    Attributes:
        spec: The specification of this controllable.
        history: All request-answer pairs observed so far.
    """

    spec: ControllableSpec
    history: list[RequestAnswerPair] = field(default_factory=list)
