"""Threat model as a budgeted access profile over tagged interfaces.

A threat model M = (C, O, F, B) defines which controllables, observables, and
feedback channels are exposed to the optimizer, plus budget constraints. Each
interface item is tagged with security domain labels drawn from a vocabulary.

The classical black/grey/white-box taxonomy is a special case: black-box
restricts C to user surfaces with minimal O and F; white-box exposes everything.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class SecurityDomain(enum.Enum):
    """Default security domain vocabulary.

    These tags annotate every controllable, observable, and feedback interface
    to indicate which security boundary it belongs to. Target modules may extend
    this with custom tags via :class:`SecurityTag`.
    """

    USER = "user"
    EXTERNAL_DATA = "external_data"
    TOOL_CATALOG = "tool_catalog"
    INTERNAL_CONTEXT = "internal_context"
    MEMORY = "memory"
    MODEL = "model"
    VERIFIER = "verifier"
    CODE = "code"


@dataclass(frozen=True)
class SecurityTag:
    """A security domain annotation on an interface item.

    Uses :class:`SecurityDomain` for standard tags, or a custom string for
    target-specific extensions.
    """

    domain: SecurityDomain | str

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecurityTag):
            return self._key == other._key
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._key)

    @property
    def _key(self) -> str:
        if isinstance(self.domain, SecurityDomain):
            return self.domain.value
        return self.domain

    def __repr__(self) -> str:
        return f"SecurityTag({self._key!r})"


# Convenience constructors for default domains
USER = SecurityTag(SecurityDomain.USER)
EXTERNAL_DATA = SecurityTag(SecurityDomain.EXTERNAL_DATA)
TOOL_CATALOG = SecurityTag(SecurityDomain.TOOL_CATALOG)
INTERNAL_CONTEXT = SecurityTag(SecurityDomain.INTERNAL_CONTEXT)
MEMORY = SecurityTag(SecurityDomain.MEMORY)
MODEL = SecurityTag(SecurityDomain.MODEL)
VERIFIER = SecurityTag(SecurityDomain.VERIFIER)
CODE = SecurityTag(SecurityDomain.CODE)


@dataclass(frozen=True)
class ThreatModel:
    """A budgeted access profile defining what the optimizer may access.

    The controller builds threat models by selecting subsets of the target's
    full interface set. The optimizer receives only what the threat model exposes.

    Attributes:
        name: Human-readable identifier (e.g. "user_only", "user+external").
        controllable_tags: Security tags for controllables exposed to optimizer.
        observable_tags: Security tags for observables exposed to optimizer.
        feedback_tags: Security tags for feedback channels exposed to optimizer.
        budget_constraints: Named budget limits (see :class:`Budget`).
        description: Optional free-text description of the threat scenario.
    """

    name: str
    controllable_tags: frozenset[SecurityTag] = field(default_factory=frozenset)
    observable_tags: frozenset[SecurityTag] = field(default_factory=frozenset)
    feedback_tags: frozenset[SecurityTag] = field(default_factory=frozenset)
    budget_constraints: dict[str, float] = field(default_factory=dict)
    description: str = ""

    def exposes_controllable(self, tag: SecurityTag) -> bool:
        """Check whether this threat model exposes a controllable with the given tag."""
        return tag in self.controllable_tags

    def exposes_observable(self, tag: SecurityTag) -> bool:
        """Check whether this threat model exposes an observable with the given tag."""
        return tag in self.observable_tags

    def exposes_feedback(self, tag: SecurityTag) -> bool:
        """Check whether this threat model exposes a feedback channel with the given tag."""
        return tag in self.feedback_tags
